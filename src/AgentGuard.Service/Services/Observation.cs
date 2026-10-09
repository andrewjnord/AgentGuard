using System.Collections.Concurrent;
using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Storage;
using AgentGuard.Service.Platform;

namespace AgentGuard.Service.Services;

/// <summary>
/// Records detect-only activity (process launches, file and network telemetry). Nothing here is held or prevented; when a
/// blocking rule matches and the "auto-suspend" setting is on, the offending agent process is suspended for review.
/// </summary>
public sealed class ObservationService
{
    private readonly EventPipeline _pipeline;
    private readonly SettingsManager _settings;
    private readonly EnforcementService _enforcement;
    private readonly ILogger<ObservationService> _log;

    public ObservationService(EventPipeline pipeline, SettingsManager settings, EnforcementService enforcement, ILogger<ObservationService> log)
    {
        _pipeline = pipeline;
        _settings = settings;
        _enforcement = enforcement;
        _log = log;
    }

    public async Task<AgentEvent> ObserveAsync(EventInput input, CancellationToken ct = default)
    {
        var decision = _pipeline.Evaluate(input);
        var suspended = false;
        if (decision.Effective == Verdict.Block && input.Pid is { } pid && _settings.Current.AutoSuspendOnDetectBlock && _enforcement.ProcessControl)
        {
            suspended = _enforcement.TrySuspendProcess(pid);
            if (suspended) _log.LogWarning("Suspended pid {Pid} ({Agent}) after a blocked {Action}: {Target}", pid, input.AgentId, input.Action, input.Target);
        }
        var details = new Dictionary<string, object?>(input.Details ?? new());
        if (suspended) details["autoSuspended"] = true;
        var withDetails = new EventInput
        {
            AgentId = input.AgentId, AgentName = input.AgentName, Pid = input.Pid, Action = input.Action, Target = input.Target,
            Details = details, Source = input.Source, UserProfile = input.UserProfile, Cwd = input.Cwd, Ts = input.Ts,
        };
        return await _pipeline.RecordAsync(withDetails, decision, enforced: suspended, ct);
    }
}

/// <summary>Turns agent process starts and exits into registry updates and events. Shared by polling discovery and real-time telemetry.</summary>
public sealed class AgentLifecycle
{
    private readonly AgentRegistry _agents;
    private readonly EventStore _store;
    private readonly EventPipeline _pipeline;
    private readonly ObservationService _observe;
    private readonly IEnforcementAdapters _adapters;
    private readonly EventBus _bus;
    private readonly ILogger<AgentLifecycle> _log;
    private readonly ConcurrentDictionary<string, byte> _signerChecked = new();
    // Agents seen running since the last "agent exited", so a burst of process exits is reported once.
    private readonly ConcurrentDictionary<string, byte> _running = new();

    public AgentLifecycle(AgentRegistry agents, EventStore store, EventPipeline pipeline, ObservationService observe, IEnforcementAdapters adapters, EventBus bus, ILogger<AgentLifecycle> log)
    {
        _agents = agents;
        _store = store;
        _pipeline = pipeline;
        _observe = observe;
        _adapters = adapters;
        _bus = bus;
        _log = log;
    }

    /// <param name="reportChildren">False on the first scan, so processes that were already running are not reported as new launches.</param>
    public async Task OnStartedAsync(AttributedProcess a, string source, bool reportChildren, CancellationToken ct = default)
    {
        var p = a.Process;
        try { _store.RecordAgentProcess(p.Pid, p.StartTime, a.AgentId, p.ParentPid, p.CommandLine, p.ExePath); }
        catch (Exception ex) { _log.LogDebug(ex, "Could not record process {Pid}.", p.Pid); }

        if (a.IsRoot)
        {
            _running[a.AgentId] = 1;
            var isNew = _agents.Ensure(a.AgentId, a.AgentName, a.Kind, p.ExePath, a.Publisher);
            InspectSigner(a.AgentId, p.ExePath);
            if (isNew)
            {
                var record = _agents.Get(a.AgentId)!;
                await _pipeline.RecordAsync(new EventInput
                {
                    AgentId = a.AgentId,
                    AgentName = a.AgentName,
                    Pid = p.Pid,
                    Action = Actions.AgentDiscovered,
                    Target = p.ExePath ?? p.Name,
                    Details = new() { ["kind"] = a.Kind, ["publisher"] = record.Publisher, ["signerValid"] = record.SignerValid, ["commandLine"] = p.CommandLine },
                    Source = EventSources.Discovery,
                }, null, enforced: false, ct);
            }
            _bus.Publish("agentChanged", a.AgentId);
            return;
        }

        if (!reportChildren || a.IsQuiet) return;
        await _observe.ObserveAsync(new EventInput
        {
            AgentId = a.AgentId,
            AgentName = a.AgentName,
            Pid = p.Pid,
            Action = a.IsShell ? Actions.ShellExec : Actions.ProcessStart,
            Target = p.CommandLine ?? p.Name,
            Details = new() { ["process"] = p.Name, ["exePath"] = p.ExePath, ["parentPid"] = p.ParentPid },
            Source = source,
            UserProfile = p.UserProfile,
        }, ct);
    }

    public async Task OnExitedAsync(AttributedProcess a, CancellationToken ct = default, bool reportAgentExit = true)
    {
        try { _store.EndAgentProcess(a.Process.Pid, a.Process.StartTime, DateTimeOffset.UtcNow); }
        catch (Exception ex) { _log.LogDebug(ex, "Could not record exit of {Pid}.", a.Process.Pid); }
        if (reportAgentExit && a.IsRoot) await OnAgentGoneAsync(a, ct);
    }

    /// <summary>Records "agent exited" once the agent has no processes left (and only once per run of the agent).</summary>
    public async Task OnAgentGoneAsync(AttributedProcess a, CancellationToken ct = default)
    {
        if (_agents.Attributor.PidsFor(a.AgentId).Count > 0) return;
        if (!_running.TryRemove(a.AgentId, out _)) return; // already reported
        var record = _agents.Get(a.AgentId);
        await _pipeline.RecordAsync(new EventInput
        {
            AgentId = a.AgentId,
            AgentName = a.AgentName,
            Pid = a.Process.Pid,
            Action = Actions.AgentExited,
            Target = record?.ExePath ?? a.Process.ExePath ?? a.Process.Name,
            Source = EventSources.Discovery,
        }, null, enforced: false, ct);
        _bus.Publish("agentChanged", a.AgentId);
    }

    private void InspectSigner(string agentId, string? exePath)
    {
        if (_adapters.FileTrust is null || string.IsNullOrEmpty(exePath) || !_signerChecked.TryAdd(agentId + "|" + exePath, 0)) return;
        try
        {
            var (publisher, valid) = _adapters.FileTrust.Inspect(exePath);
            _agents.SetSigner(agentId, publisher, valid);
        }
        catch (Exception ex) { _log.LogDebug(ex, "Signature check failed for {Path}.", exePath); }
    }
}
