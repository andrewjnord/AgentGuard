using AgentGuard.Core;
using AgentGuard.Core.Policy;
using AgentGuard.Core.Storage;

namespace AgentGuard.Service.Services;

public sealed class EventInput
{
    public string AgentId { get; init; } = "";
    public string AgentName { get; init; } = "";
    public int? Pid { get; init; }
    public string Action { get; init; } = "";
    public string Target { get; init; } = "";
    public Dictionary<string, object?>? Details { get; init; }
    public string Source { get; init; } = EventSources.System;
    public string? UserProfile { get; init; }
    public string? Cwd { get; init; }
    /// <summary>Override the timestamp (demo history only).</summary>
    public DateTimeOffset? Ts { get; init; }
}

/// <summary>Kill switch: while engaged, every action checked through the MCP proxy or hooks is blocked.</summary>
public sealed class KillSwitch
{
    private const string Key = "killswitch";
    private readonly EventStore _store;

    public bool Engaged { get; private set; }
    public DateTimeOffset? Since { get; private set; }

    public KillSwitch(EventStore store)
    {
        _store = store;
        var saved = store.GetSetting(Key);
        if (saved is not null && DateTimeOffset.TryParse(saved, out var since)) { Engaged = true; Since = since; }
    }

    public void Engage()
    {
        if (Engaged) return;
        Engaged = true;
        Since = DateTimeOffset.UtcNow;
        _store.SetSetting(Key, Since.Value.ToString("O"));
    }

    public void Release()
    {
        Engaged = false;
        Since = null;
        _store.SetSetting(Key, "");
    }
}

/// <summary>Central path for every event: policy evaluation, redaction, storage, alerts and live publication.</summary>
public sealed class EventPipeline : IPolicyContext
{
    private readonly EventStore _store;
    private readonly PolicyManager _policy;
    private readonly SettingsManager _settings;
    private readonly AgentRegistry _agents;
    private readonly KillSwitch _killSwitch;
    private readonly EventBus _bus;

    public EventPipeline(EventStore store, PolicyManager policy, SettingsManager settings, AgentRegistry agents, KillSwitch killSwitch, EventBus bus)
    {
        _store = store;
        _policy = policy;
        _settings = settings;
        _agents = agents;
        _killSwitch = killSwitch;
        _bus = bus;
    }

    public bool IsFirstContact(string agentId, string host) => !_store.HasHostContact(agentId, host);

    public PolicyDecision Evaluate(EventInput input) =>
        _policy.Engine.Evaluate(new PolicyInput(
            input.AgentId, input.Action, input.Target, input.Details, input.UserProfile, input.Cwd,
            _agents.TrustOf(input.AgentId), _killSwitch.Engaged), this);

    /// <summary>Evaluates and records an observed event (nothing is held or prevented).</summary>
    public async Task<(AgentEvent Event, PolicyDecision Decision)> ObserveAsync(EventInput input, CancellationToken ct = default)
    {
        var decision = Evaluate(input);
        var e = await RecordAsync(input, decision, enforced: false, ct);
        return (e, decision);
    }

    public async Task<AgentEvent> RecordAsync(EventInput input, PolicyDecision? decision, bool enforced, CancellationToken ct = default)
    {
        var redactor = _settings.Redactor;
        var details = redactor.Redact(Json.Normalize(input.Details));
        if (decision is not null && decision.RuleVerdict != decision.Effective)
            details["policyVerdict"] = decision.RuleVerdict.ToString().ToLowerInvariant();
        if (decision?.RuleId is not null) details["reason"] = decision.Reason;
        if (!string.IsNullOrEmpty(input.Cwd)) details["cwd"] = input.Cwd;

        var e = new AgentEvent
        {
            Ts = input.Ts ?? DateTimeOffset.UtcNow,
            AgentId = input.AgentId,
            AgentName = string.IsNullOrEmpty(input.AgentName) ? input.AgentId : input.AgentName,
            Pid = input.Pid,
            Action = input.Action,
            Target = redactor.Redact(input.Target),
            Details = details,
            Verdict = decision?.Effective ?? Verdict.Log,
            RuleId = decision?.RuleId,
            Severity = decision?.Severity ?? Severity.Info,
            Source = input.Source,
            Enforced = enforced,
        };
        e = await _store.AppendAsync(e, ct);

        if (input.Action == Actions.NetConnect && PolicyEngine.HostOf(new PolicyInput(input.AgentId, input.Action, input.Target, input.Details)) is { } host)
            _store.RecordHostContact(input.AgentId, host);

        _bus.Publish("event", e);
        if (decision?.Alert == true) RaiseAlert(e);
        return e;
    }

    public Task<AgentEvent> SystemEventAsync(string action, string target, Dictionary<string, object?>? details = null, Severity severity = Severity.Info) =>
        RecordAsync(new EventInput
        {
            AgentId = "agentguard",
            AgentName = "AgentGuard",
            Action = action,
            Target = target,
            Details = details,
            Source = EventSources.System,
        }, new PolicyDecision(Verdict.Log, Verdict.Log, null, severity, false, "", 0, Verdict.Block), enforced: false);

    private void RaiseAlert(AgentEvent e)
    {
        var alert = _store.AddAlert(new AlertRecord
        {
            EventId = e.Id,
            Ts = e.Ts,
            Severity = e.Severity < Severity.Low ? Severity.Low : e.Severity,
            Status = "open",
            Title = AlertTitle(e),
            AgentId = e.AgentId,
            AgentName = e.AgentName,
            Action = e.Action,
            Target = e.Target,
            RuleId = e.RuleId,
        });
        _bus.Publish("alert", alert);
    }

    public static string AlertTitle(AgentEvent e)
    {
        var what = e.Action switch
        {
            Actions.FileRead => "read",
            Actions.FileWrite => "write to",
            Actions.FileDelete => "delete",
            Actions.ShellExec or Actions.ProcessStart => "run",
            Actions.NetConnect => "connect to",
            Actions.McpCall => "call tool",
            _ => e.Action,
        };
        var outcome = e.Verdict switch
        {
            Verdict.Block when e.Enforced => "Blocked",
            Verdict.Block => "Flagged",
            Verdict.Ask => "Approval needed",
            _ => "Flagged",
        };
        var target = e.Target.Length > 80 ? e.Target[..80] + "…" : e.Target;
        return $"{outcome}: {e.AgentName} tried to {what} {target}";
    }
}
