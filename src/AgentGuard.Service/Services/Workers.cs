using System.Collections.Concurrent;
using System.Threading.Channels;
using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Export;
using AgentGuard.Core.Integration;
using AgentGuard.Core.Storage;
using AgentGuard.Service.Api;
using AgentGuard.Service.Platform;

namespace AgentGuard.Service.Services;

/// <summary>Runs once at start: publishes the client config, resumes processes a previous run left suspended, records the start.</summary>
public sealed class StartupTasks : IHostedService
{
    private readonly AgentGuardOptions _options;
    private readonly SettingsManager _settings;
    private readonly EnforcementService _enforcement;
    private readonly KillSwitch _killSwitch;
    private readonly EventPipeline _pipeline;
    private readonly PolicyManager _policy;
    private readonly IEnforcementAdapters _adapters;
    private readonly ILogger<StartupTasks> _log;

    public StartupTasks(AgentGuardOptions options, SettingsManager settings, EnforcementService enforcement, KillSwitch killSwitch,
        EventPipeline pipeline, PolicyManager policy, IEnforcementAdapters adapters, ILogger<StartupTasks> log)
    {
        _options = options;
        _settings = settings;
        _enforcement = enforcement;
        _killSwitch = killSwitch;
        _pipeline = pipeline;
        _policy = policy;
        _adapters = adapters;
        _log = log;
    }

    public async Task StartAsync(CancellationToken ct)
    {
        WriteClientConfig(_settings.Current);
        _settings.Changed += WriteClientConfig;
        var resumed = 0;
        try { resumed = _enforcement.RecoverAfterRestart(_killSwitch.Engaged); }
        catch (Exception ex) { _log.LogWarning(ex, "Could not resume processes suspended by a previous run."); }
        await _pipeline.SystemEventAsync(Actions.System, "AgentGuard service started", new()
        {
            ["version"] = StatusService.Version,
            ["mode"] = _policy.Mode.ToString().ToLowerInvariant(),
            ["policyVersion"] = _policy.Current.Version,
            ["killSwitch"] = _killSwitch.Engaged,
            ["telemetry"] = _adapters.Telemetry,
            ["processControl"] = _adapters.ProcessControl,
            ["firewall"] = _adapters.Firewall,
            ["resumedAfterRestart"] = resumed,
            ["demo"] = _options.Demo,
        });
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;

    private void WriteClientConfig(AgentGuardSettings s)
    {
        try
        {
            Directory.CreateDirectory(_options.PublicDir);
            if (OperatingSystem.IsWindows()) PublicDirAcl.Apply(_options.PublicDir);
            var config = new ClientConfig { Port = _options.Port, FailMode = s.FailMode, Version = StatusService.Version };
            var tmp = _options.ClientConfigPath + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(config));
            File.Move(tmp, _options.ClientConfigPath, overwrite: true);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Could not write {Path}.", _options.ClientConfigPath); }
    }
}

/// <summary>Polls the process list, attributes processes to agents and reports launches and exits.</summary>
public sealed class DiscoveryWorker : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(3);

    private readonly IProcessSource _source;
    private readonly AgentRegistry _agents;
    private readonly AgentLifecycle _lifecycle;
    private readonly ILogger<DiscoveryWorker> _log;

    public DiscoveryWorker(IProcessSource source, AgentRegistry agents, AgentLifecycle lifecycle, ILogger<DiscoveryWorker> log)
    {
        _source = source;
        _agents = agents;
        _lifecycle = lifecycle;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var first = true;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await ScanAsync(first, ct);
                first = false;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Process scan failed."); }
            await Task.Delay(Interval, ct).ContinueWith(_ => { });
        }
    }

    public async Task ScanAsync(bool first, CancellationToken ct = default)
    {
        var snapshot = await Task.Run(_source.Snapshot, ct);
        var diff = _agents.Attributor.Update(snapshot);
        foreach (var a in diff.Started.OrderBy(a => a.Process.StartTime))
            await _lifecycle.OnStartedAsync(a, EventSources.Discovery, reportChildren: !first, ct);
        foreach (var a in diff.Exited)
            await _lifecycle.OnExitedAsync(a, ct, reportAgentExit: false);
        // One "agent exited" per agent, not one per process: apps like VS Code run a dozen matching processes.
        foreach (var agent in diff.Exited.Where(a => a.IsRoot).GroupBy(a => a.AgentId))
            await _lifecycle.OnAgentGoneAsync(agent.First(), ct);
    }
}

/// <summary>Real-time OS activity from the telemetry adapter (ETW on Windows), attributed to agents and recorded as detect-only events.</summary>
public sealed class TelemetryWorker : BackgroundService
{
    private const int PerAgentPerMinute = 600;

    private readonly IEnforcementAdapters _adapters;
    private readonly AgentRegistry _agents;
    private readonly AgentLifecycle _lifecycle;
    private readonly ObservationService _observe;
    private readonly EventPipeline _pipeline;
    private readonly ILogger<TelemetryWorker> _log;
    private readonly Channel<TelemetryEvent> _queue = Channel.CreateBounded<TelemetryEvent>(new BoundedChannelOptions(20_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recent = new();
    private readonly Dictionary<string, (DateTimeOffset Window, int Count, bool Warned)> _budget = new();

    public TelemetryWorker(IEnforcementAdapters adapters, AgentRegistry agents, AgentLifecycle lifecycle, ObservationService observe, EventPipeline pipeline, ILogger<TelemetryWorker> log)
    {
        _adapters = adapters;
        _agents = agents;
        _lifecycle = lifecycle;
        _observe = observe;
        _pipeline = pipeline;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (_adapters.TelemetryFactory is not { } factory) return;
        ITelemetrySource? source = null;
        try
        {
            source = factory();
            source.Start(e => _queue.Writer.TryWrite(e), pid => _agents.Attributor.Get(pid) is not null, ex => _log.LogWarning(ex, "Telemetry error."));
            _log.LogInformation("Real-time telemetry started.");
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Real-time telemetry could not start; process discovery continues by polling.");
            source?.Dispose();
            return;
        }

        try
        {
            await foreach (var e in _queue.Reader.ReadAllAsync(ct))
            {
                try { await HandleAsync(e, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogDebug(ex, "Telemetry event dropped."); }
            }
        }
        catch (OperationCanceledException) { }
        finally { source.Dispose(); }
    }

    private async Task HandleAsync(TelemetryEvent e, CancellationToken ct)
    {
        switch (e.Kind)
        {
            case TelemetryKinds.ProcessStart when e.Process is not null:
                if (_agents.Attributor.Add(e.Process) is { } started) await _lifecycle.OnStartedAsync(started, EventSources.Etw, reportChildren: true, ct);
                return;
            case TelemetryKinds.ProcessStop:
                if (_agents.Attributor.Remove(e.Pid) is { } stopped) await _lifecycle.OnExitedAsync(stopped, ct);
                return;
        }

        var a = _agents.Attributor.Get(e.Pid);
        if (a is null || a.IsQuiet) return;

        // Same process, same action, same target within 10 seconds: one event is enough.
        var key = $"{e.Pid}|{e.Kind}|{e.Target}";
        if (_recent.TryGetValue(key, out var last) && e.Ts - last < TimeSpan.FromSeconds(10)) return;
        _recent[key] = e.Ts;
        if (_recent.Count > 50_000) _recent.Clear();

        if (!WithinBudget(a, e.Ts))
        {
            if (!_budget[a.AgentId].Warned)
            {
                _budget[a.AgentId] = _budget[a.AgentId] with { Warned = true };
                await _pipeline.RecordAsync(Endpoints.SystemInput(_agents.Get(a.AgentId) ?? new AgentRecord { Id = a.AgentId, Name = a.AgentName },
                    $"Telemetry for {a.AgentName} throttled (over {PerAgentPerMinute} events per minute)", new() { ["limit"] = PerAgentPerMinute }), Endpoints.LogDecision(Severity.Low), false, ct);
            }
            return;
        }

        await _observe.ObserveAsync(new EventInput
        {
            AgentId = a.AgentId,
            AgentName = a.AgentName,
            Pid = e.Pid,
            Action = e.Kind,
            Target = e.Target,
            Details = e.Details?.ToDictionary(kv => kv.Key, kv => kv.Value) ?? new(),
            Source = EventSources.Etw,
            UserProfile = a.Process.UserProfile,
        }, ct);
    }

    private bool WithinBudget(AttributedProcess a, DateTimeOffset now)
    {
        if (!_budget.TryGetValue(a.AgentId, out var b) || now - b.Window > TimeSpan.FromMinutes(1)) b = (now, 0, false);
        b.Count++;
        _budget[a.AgentId] = b;
        return b.Count <= PerAgentPerMinute;
    }
}

/// <summary>Finds MCP servers at start and every few minutes.</summary>
public sealed class McpScanWorker : BackgroundService
{
    private readonly McpManager _mcp;
    private readonly ILogger<McpScanWorker> _log;

    public McpScanWorker(McpManager mcp, ILogger<McpScanWorker> log)
    {
        _mcp = mcp;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { _mcp.Rescan(); }
            catch (Exception ex) { _log.LogWarning(ex, "MCP config scan failed."); }
            await Task.Delay(TimeSpan.FromMinutes(5), ct).ContinueWith(_ => { });
        }
    }
}

/// <summary>Pushes new events to the enabled SIEM exporters, each with its own cursor so one slow target never holds up another.</summary>
public sealed class ExportWorker : BackgroundService
{
    private readonly EventStore _store;
    private readonly SettingsManager _settings;
    private readonly ILogger<ExportWorker> _log;
    private readonly Dictionary<string, (string Config, IEventExporter Exporter)> _exporters = new();
    private readonly Dictionary<string, (DateTimeOffset RetryAt, int Failures)> _backoff = new();

    public ExportWorker(EventStore store, SettingsManager settings, ILogger<ExportWorker> log)
    {
        _store = store;
        _settings = settings;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await RunOnceAsync(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Export cycle failed."); }
            await Task.Delay(TimeSpan.FromSeconds(5), ct).ContinueWith(_ => { });
        }
        foreach (var (_, x) in _exporters) (x.Exporter as IDisposable)?.Dispose();
    }

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var s = _settings.Current;
        var host = Environment.MachineName;
        var wanted = new Dictionary<string, (string Config, Func<IEventExporter> Create)>();
        if (s.Exports.Splunk.Enabled) wanted["splunk"] = (Json.Serialize(s.Exports.Splunk), () => new SplunkHecExporter(s.Exports.Splunk, host, StatusService.Version));
        if (s.Exports.Syslog.Enabled) wanted["syslog"] = (Json.Serialize(s.Exports.Syslog), () => new SyslogExporter(s.Exports.Syslog, host, StatusService.Version));
        if (s.Exports.JsonFile.Enabled) wanted["jsonFile"] = (Json.Serialize(s.Exports.JsonFile), () => new JsonFileExporter(s.Exports.JsonFile.Directory, host, StatusService.Version));

        foreach (var name in _exporters.Keys.Except(wanted.Keys).ToList())
        {
            (_exporters[name].Exporter as IDisposable)?.Dispose();
            _exporters.Remove(name);
        }

        foreach (var (name, want) in wanted)
        {
            if (!_exporters.TryGetValue(name, out var current) || current.Config != want.Config)
            {
                (current.Exporter as IDisposable)?.Dispose();
                _exporters[name] = (want.Config, want.Create());
                _backoff.Remove(name);
            }
            if (_backoff.TryGetValue(name, out var b) && DateTimeOffset.UtcNow < b.RetryAt) continue;

            var cursorKey = "export.cursor." + name;
            if (!long.TryParse(_store.GetSetting(cursorKey), out var cursor))
            {
                // A newly enabled target starts from now rather than replaying the whole history (use /api/v1/export for that).
                cursor = _store.QueryEvents(new EventFilter { Limit = 1 }).FirstOrDefault()?.Id ?? 0;
                _store.SetSetting(cursorKey, cursor.ToString());
            }
            var batch = _store.QueryEvents(new EventFilter { After = cursor, Ascending = true, Limit = 500 });
            if (batch.Count == 0) continue;
            try
            {
                await _exporters[name].Exporter.ExportAsync(batch, ct);
                _store.SetSetting(cursorKey, batch[^1].Id.ToString());
                _backoff.Remove(name);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                var failures = (_backoff.TryGetValue(name, out var prev) ? prev.Failures : 0) + 1;
                var delay = TimeSpan.FromSeconds(Math.Min(300, 5 * Math.Pow(2, Math.Min(failures, 6))));
                _backoff[name] = (DateTimeOffset.UtcNow + delay, failures);
                if (failures is 1 or 5 or 20) _log.LogWarning(ex, "Export to {Target} failed ({Failures} in a row); retrying in {Delay}.", name, failures, delay);
            }
        }
    }
}

/// <summary>Daily retention pruning and audit-log integrity check.</summary>
public sealed class MaintenanceWorker : BackgroundService
{
    private readonly EventStore _store;
    private readonly SettingsManager _settings;
    private readonly IServiceProvider _services;
    private readonly ILogger<MaintenanceWorker> _log;

    public MaintenanceWorker(EventStore store, SettingsManager settings, IServiceProvider services, ILogger<MaintenanceWorker> log)
    {
        _store = store;
        _settings = settings;
        _services = services;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Delay(TimeSpan.FromSeconds(30), ct).ContinueWith(_ => { });
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var removed = await _store.PruneAsync(DateTimeOffset.UtcNow.AddDays(-_settings.Current.RetentionDays), ct);
                if (removed > 0) _log.LogInformation("Retention: removed {Count} events older than {Days} days.", removed, _settings.Current.RetentionDays);
                await _services.GetRequiredService<Ops>().VerifyIntegrityAsync();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Maintenance failed."); }
            await Task.Delay(TimeSpan.FromHours(24), ct).ContinueWith(_ => { });
        }
    }
}

/// <summary>Publishes a status update every 10 seconds for live views.</summary>
public sealed class StatusTicker : BackgroundService
{
    private readonly EventBus _bus;
    public StatusTicker(EventBus bus) => _bus = bus;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        while (await timer.WaitForNextTickAsync(ct).AsTask().ContinueWith(t => !t.IsCanceled && t.Result))
            if (_bus.SubscriberCount > 0) _bus.Publish("status", "");
    }
}
