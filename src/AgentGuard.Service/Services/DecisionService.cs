using System.Collections.Concurrent;
using AgentGuard.Core;
using AgentGuard.Core.Policy;
using AgentGuard.Core.Storage;

namespace AgentGuard.Service.Services;

/// <summary>Holds "ask" decisions until a person answers or the timeout passes.</summary>
public sealed class ApprovalBroker
{
    private readonly EventStore _store;
    private readonly EventBus _bus;
    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _pending = new();

    public ApprovalBroker(EventStore store, EventBus bus)
    {
        _store = store;
        _bus = bus;
        // Approvals left pending by a previous run can never be answered now.
        foreach (var a in store.ListApprovals("pending"))
        {
            a.Status = "expired";
            a.Decision = "timeout";
            a.DecidedAt = DateTimeOffset.UtcNow;
            a.DecidedBy = "system";
            store.SaveApproval(a);
        }
    }

    public int PendingCount => _pending.Count;

    public ApprovalRecord Create(AgentEvent e, int timeoutSeconds)
    {
        var a = new ApprovalRecord
        {
            EventId = e.Id,
            RequestedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(timeoutSeconds),
            AgentId = e.AgentId,
            AgentName = e.AgentName,
            Action = e.Action,
            Target = e.Target,
            Details = e.Details,
            RuleId = e.RuleId,
        };
        _pending[a.Id] = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        _store.SaveApproval(a);
        _bus.Publish("approval", a);
        return a;
    }

    /// <summary>Waits for a decision: "allow_once", "allow_always", "deny", or "timeout".</summary>
    public async Task<string> WaitAsync(ApprovalRecord a, CancellationToken ct)
    {
        if (!_pending.TryGetValue(a.Id, out var tcs)) return "timeout";
        var delay = a.ExpiresAt - DateTimeOffset.UtcNow;
        if (delay < TimeSpan.Zero) delay = TimeSpan.Zero;
        var finished = await Task.WhenAny(tcs.Task, Task.Delay(delay, ct));
        _pending.TryRemove(a.Id, out _);
        return finished == tcs.Task ? tcs.Task.Result : "timeout";
    }

    /// <summary>Records a person's decision. Returns null when the approval is unknown or already closed.</summary>
    public bool Decide(string id, string decision) =>
        _pending.TryGetValue(id, out var tcs) && tcs.TrySetResult(decision);

    public ApprovalRecord Close(ApprovalRecord a, string decision, string decidedBy)
    {
        a.Decision = decision;
        a.DecidedAt = DateTimeOffset.UtcNow;
        a.DecidedBy = decidedBy;
        a.Status = decision switch
        {
            "allow_once" or "allow_always" => "allowed",
            "deny" => "denied",
            _ => "expired",
        };
        _store.SaveApproval(a);
        _bus.Publish("approval", a);
        return a;
    }
}

/// <summary>Answers the MCP proxy and hooks: evaluate, record, and for "ask" hold until a person decides.</summary>
public sealed class DecisionService
{
    private readonly EventPipeline _pipeline;
    private readonly ApprovalBroker _approvals;
    private readonly PolicyManager _policy;
    private readonly SettingsManager _settings;
    private readonly AgentRegistry _agents;
    private readonly EventBus _bus;
    private readonly ConcurrentDictionary<string, string> _decidedBy = new();

    public DecisionService(EventPipeline pipeline, ApprovalBroker approvals, PolicyManager policy, SettingsManager settings, AgentRegistry agents, EventBus bus)
    {
        _pipeline = pipeline;
        _approvals = approvals;
        _policy = policy;
        _settings = settings;
        _agents = agents;
        _bus = bus;
    }

    public async Task<DecideResponse> DecideAsync(DecideRequest req, CancellationToken ct)
    {
        var agentName = req.AgentName ?? req.AgentId;
        var kind = req.AgentId.StartsWith("mcp:", StringComparison.Ordinal) ? AgentKinds.McpServer
            : req.Source == EventSources.Hook ? AgentKinds.Cli : AgentKinds.Unknown;
        if (_agents.Ensure(req.AgentId, agentName, kind)) _bus.Publish("agentChanged", req.AgentId);
        if (req.Source == EventSources.Hook) _agents.MarkHookSeen(req.AgentId);

        var input = new EventInput
        {
            AgentId = req.AgentId,
            AgentName = agentName,
            Pid = req.Pid,
            Action = req.Action,
            Target = req.Target,
            Details = req.Details,
            Source = req.Source,
            UserProfile = req.UserProfile,
            Cwd = req.Cwd,
        };
        var decision = _pipeline.Evaluate(input);
        var holds = decision.Effective is Verdict.Block or Verdict.Ask;
        var e = await _pipeline.RecordAsync(input, decision, enforced: holds, ct);

        if (decision.Effective != Verdict.Ask)
        {
            var allowed = decision.Effective != Verdict.Block;
            return new DecideResponse
            {
                Verdict = allowed ? "allow" : "block",
                PolicyVerdict = decision.RuleVerdict,
                RuleId = decision.RuleId,
                Reason = allowed ? decision.Reason : "Blocked by AgentGuard: " + decision.Reason,
                EventId = e.Id,
            };
        }

        var timeout = decision.TimeoutSeconds > 0 ? decision.TimeoutSeconds : _settings.Current.ApprovalTimeoutSeconds;
        var approval = _approvals.Create(e, timeout);
        if (req.Wait == false)
        {
            return new DecideResponse
            {
                Verdict = "block",
                PolicyVerdict = Verdict.Ask,
                RuleId = decision.RuleId,
                Reason = "Waiting for approval in AgentGuard.",
                EventId = e.Id,
                ApprovalId = approval.Id,
            };
        }

        var answer = await _approvals.WaitAsync(approval, ct);
        var by = _decidedBy.TryRemove(approval.Id, out var who) ? who : answer == "timeout" ? "timeout" : "user";
        _approvals.Close(approval, answer, by);

        var final = answer switch
        {
            "allow_once" or "allow_always" => true,
            "deny" => false,
            _ => decision.OnTimeout == Verdict.Allow,
        };
        string? addedRule = null;
        if (answer == "allow_always") addedRule = _policy.AddAllowRule(req.AgentId, req.Action, req.Target, by);

        await _pipeline.RecordAsync(new EventInput
        {
            AgentId = req.AgentId,
            AgentName = agentName,
            Pid = req.Pid,
            Action = Actions.ApprovalDecided,
            Target = req.Target,
            Details = new()
            {
                ["approvalId"] = approval.Id,
                ["eventId"] = e.Id,
                ["requestedAction"] = req.Action,
                ["decision"] = answer,
                ["decidedBy"] = by,
                ["addedRule"] = addedRule,
            },
            Source = EventSources.System,
        }, new PolicyDecision(final ? Verdict.Allow : Verdict.Block, final ? Verdict.Allow : Verdict.Block, decision.RuleId, decision.Severity, false, "", 0, Verdict.Block), enforced: true, ct);

        return new DecideResponse
        {
            Verdict = final ? "allow" : "block",
            PolicyVerdict = Verdict.Ask,
            RuleId = decision.RuleId,
            Reason = answer switch
            {
                "allow_once" => "Approved once by the user in AgentGuard.",
                "allow_always" => "Approved permanently by the user in AgentGuard.",
                "deny" => "Blocked by AgentGuard: the user denied this action.",
                _ => final ? "Approval timed out; allowed by policy." : "Blocked by AgentGuard: no approval within " + timeout + " seconds.",
            },
            EventId = e.Id,
            ApprovalId = approval.Id,
        };
    }

    /// <summary>Called from the API when a person answers an approval.</summary>
    public bool Answer(string approvalId, string decision, string decidedBy)
    {
        _decidedBy[approvalId] = decidedBy;
        if (_approvals.Decide(approvalId, decision)) return true;
        _decidedBy.TryRemove(approvalId, out _);
        return false;
    }
}
