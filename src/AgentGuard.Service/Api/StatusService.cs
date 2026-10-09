using AgentGuard.Core;
using AgentGuard.Core.Storage;
using AgentGuard.Service.Platform;
using AgentGuard.Service.Services;

namespace AgentGuard.Service.Api;

public sealed record AgentDto(
    string Id, string Kind, string Name, string? ExePath, string? Publisher, bool? SignerValid,
    DateTimeOffset FirstSeen, DateTimeOffset LastSeen, string Trust, bool Running, IReadOnlyList<int> Pids,
    bool NetworkBlocked, EnforcementDto Enforcement, long EventCount24h, long BlockedCount24h, IReadOnlyList<string> McpServerIds);

public sealed record EnforcementDto(bool Hooks, bool McpProxy, bool Firewall, bool ProcessControl, bool FileDetectOnly);

public sealed record McpServerDto(
    string Id, string Name, string Client, string ConfigPath, string Scope, string Transport, string? Command,
    IReadOnlyList<string> Args, string? Url, bool Proxied, string AgentId, DateTimeOffset? LastCallAt);

/// <summary>Builds the status and agent views the dashboard and tray read.</summary>
public sealed class StatusService
{
    public const string Version = "0.1.0";

    private readonly EventStore _store;
    private readonly PolicyManager _policy;
    private readonly AgentRegistry _agents;
    private readonly McpManager _mcp;
    private readonly KillSwitch _killSwitch;
    private readonly ApprovalBroker _approvals;
    private readonly IEnforcementAdapters _adapters;
    private readonly AgentGuardOptions _options;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;

    public DateTimeOffset? LastIntegrityCheck { get; set; }
    public bool? LastIntegrityOk { get; set; }

    public StatusService(EventStore store, PolicyManager policy, AgentRegistry agents, McpManager mcp, KillSwitch killSwitch,
        ApprovalBroker approvals, IEnforcementAdapters adapters, AgentGuardOptions options)
    {
        _store = store;
        _policy = policy;
        _agents = agents;
        _mcp = mcp;
        _killSwitch = killSwitch;
        _approvals = approvals;
        _adapters = adapters;
        _options = options;
    }

    public object Status()
    {
        var todayStart = new DateTimeOffset(DateTime.Now.Date, TimeZoneInfo.Local.GetUtcOffset(DateTime.Now));
        var (events, blocked, asked) = _store.CountsSince(todayStart);
        var agents = _agents.All().Where(a => a.Id != "agentguard").ToList();
        var servers = _mcp.List();
        return new
        {
            version = Version,
            mode = _policy.Mode.ToString().ToLowerInvariant(),
            platform = OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsMacOS() ? "macos" : "other",
            devMode = _options.DevMode || _options.Demo,
            startedAt = _startedAt,
            uptimeSeconds = (long)(DateTimeOffset.UtcNow - _startedAt).TotalSeconds,
            counts = new
            {
                agents = agents.Count,
                activeAgents = agents.Count(a => _agents.IsRunning(a.Id)),
                mcpServers = servers.Count,
                proxiedMcpServers = servers.Count(s => s.Proxied),
                eventsToday = events,
                blockedToday = blocked,
                askedToday = asked,
                openAlerts = _store.CountAlerts("open"),
                pendingApprovals = _approvals.PendingCount,
            },
            killSwitch = new { engaged = _killSwitch.Engaged, since = _killSwitch.Since, suspendedPids = 0 },
            integrity = new { lastVerifiedAt = LastIntegrityCheck, ok = LastIntegrityOk },
            capabilities = new
            {
                etw = _adapters.Telemetry,
                firewall = _adapters.Firewall,
                processControl = _adapters.ProcessControl,
                hooks = true,
                mcpProxy = true,
            },
        };
    }

    public List<AgentDto> Agents()
    {
        var activity = _store.AgentActivity(DateTimeOffset.UtcNow.AddHours(-24)).ToDictionary(a => a.AgentId);
        var servers = _mcp.List();
        return _agents.All().Where(a => a.Id != "agentguard").Select(a => ToDto(a, activity, servers)).ToList();
    }

    public AgentDto? Agent(string id)
    {
        var a = _agents.Get(id);
        if (a is null) return null;
        var activity = _store.AgentActivity(DateTimeOffset.UtcNow.AddHours(-24)).ToDictionary(x => x.AgentId);
        return ToDto(a, activity, _mcp.List());
    }

    private AgentDto ToDto(AgentRecord a, Dictionary<string, AgentActivity> activity, List<McpServerRecord> servers)
    {
        var related = servers.Where(s => McpManager.AgentForClient(s.Client) == a.Id || s.AgentId == a.Id).ToList();
        var proxied = a.Id.StartsWith("mcp:", StringComparison.Ordinal)
            ? servers.Any(s => s.AgentId == a.Id && s.Proxied) || activity.ContainsKey(a.Id)
            : related.Any(s => s.Proxied);
        var hooks = _agents.HookSeen(a.Id);
        activity.TryGetValue(a.Id, out var act);
        return new AgentDto(a.Id, a.Kind, a.Name, a.ExePath, a.Publisher, a.SignerValid, a.FirstSeen, a.LastSeen, a.Trust,
            _agents.IsRunning(a.Id), _agents.Pids(a.Id), false,
            new EnforcementDto(hooks, proxied, _adapters.Firewall, _adapters.ProcessControl, !hooks && !proxied),
            act?.Total ?? 0, act?.Blocked ?? 0, related.Select(s => s.Id).ToList());
    }

    public static McpServerDto ToDto(McpServerRecord s) =>
        new(s.Id, s.Name, s.Client, s.ConfigPath, s.Scope, s.Transport, s.Command, s.Args, s.Proxied && s.UpstreamUrl is not null ? s.UpstreamUrl : s.Url, s.Proxied, s.AgentId, s.LastCallAt);
}
