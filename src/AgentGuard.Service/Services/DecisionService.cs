using System.Collections.Concurrent;
using AgentGuard.Core;
using AgentGuard.Core.Policy;
using AgentGuard.Core.Storage;

namespace AgentGuard.Service.Services;

/// <summary>Holds "ask" decisions until a person answers, the timeout passes, or the kill switch denies them.</summary>
public sealed class ApprovalBroker
{
    private readonly EventStore _store;
    private readonly EventBus _bus;
    private readonly ConcurrentDictionary<string, (ApprovalRecord Record, TaskCompletionSource<string> Done)> _pending = new();

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

    public IReadOnlyList<string> PendingIds => _pending.Keys.ToList();

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
        _pending[a.Id] = (a, new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously));
        _store.SaveApproval(a);
        _bus.Publish("approval", a);
        return a;
    }

    /// <summary>Waits for the decision: "allow_once", "allow_always", "deny" or "timeout". Cancellation only stops waiting; the approval stays open until it expires.</summary>
    public async Task<string> WaitAsync(string id, CancellationToken ct)
    {
        if (!_pending.TryGetValue(id, out var entry))
            return _store.GetApproval(id)?.Decision ?? "timeout";
        return await entry.Done.Task.WaitAsync(ct);
    }

    /// <summary>Closes a pending approval exactly once. Returns the closed record, or null when it was unknown or already closed.</summary>
    public ApprovalRecord? Resolve(string id, string decision, string decidedBy)
    {
        if (!_pending.TryRemove(id, out var entry)) return null;
        var a = entry.Record;
        // The kill switch is recorded as a denial; waiters still learn the real cause.
        a.Decision = decision == "killswitch" ? "deny" : decision;
        a.DecidedAt = DateTimeOffset.UtcNow;
        a.DecidedBy = decidedBy;
        a.Status = decision switch
        {
            "allow_once" or "allow_always" => "allowed",
            "deny" or "killswitch" => "denied",
            _ => "expired",
        };
        _store.SaveApproval(a);
        _bus.Publish("approval", a);
        entry.Done.TrySetResult(decision);
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
    private readonly McpManager _mcp;
    private readonly EventBus _bus;
    private readonly ILogger<DecisionService> _log;
    private readonly ConcurrentDictionary<string, (DecideRequest Request, PolicyDecision Decision, long EventId)> _context = new();

    public DecisionService(EventPipeline pipeline, ApprovalBroker approvals, PolicyManager policy, SettingsManager settings,
        AgentRegistry agents, McpManager mcp, EventBus bus, ILogger<DecisionService> log)
    {
        _pipeline = pipeline;
        _approvals = approvals;
        _policy = policy;
        _settings = settings;
        _agents = agents;
        _mcp = mcp;
        _bus = bus;
        _log = log;
    }

    public async Task<DecideResponse> DecideAsync(DecideRequest req, CancellationToken ct)
    {
        var agentName = string.IsNullOrWhiteSpace(req.AgentName) ? req.AgentId : req.AgentName;
        var kind = req.AgentId.StartsWith("mcp:", StringComparison.Ordinal) ? AgentKinds.McpServer
            : req.Source == EventSources.Hook ? AgentKinds.Cli : AgentKinds.Unknown;
        if (_agents.Ensure(req.AgentId, agentName, kind)) _bus.Publish("agentChanged", req.AgentId);
        if (req.Source == EventSources.Hook) _agents.MarkHookSeen(req.AgentId);
        if (req.Action == Actions.McpCall) _mcp.TouchCall(req.AgentId);

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
        // The request is already in flight: record it even if the caller goes away.
        var e = await _pipeline.RecordAsync(input, decision, enforced: holds, CancellationToken.None);

        if (decision.Effective != Verdict.Ask)
        {
            var allowed = decision.Effective != Verdict.Block;
            return new DecideResponse
            {
                Verdict = allowed ? "allow" : "block",
                PolicyVerdict = decision.RuleVerdict,
                RuleId = decision.RuleId,
                Reason = allowed ? (decision.Reason.Length > 0 ? decision.Reason : "Allowed by AgentGuard.") : "Blocked by AgentGuard: " + decision.Reason,
                EventId = e.Id,
            };
        }

        var timeout = decision.TimeoutSeconds > 0 ? decision.TimeoutSeconds : _settings.Current.ApprovalTimeoutSeconds;
        var approval = _approvals.Create(e, timeout);
        _context[approval.Id] = (req, decision, e.Id);
        _ = ExpireLaterAsync(approval.Id, TimeSpan.FromSeconds(timeout));

        if (req.Wait == false)
        {
            return new DecideResponse
            {
                Verdict = "block",
                PolicyVerdict = Verdict.Ask,
                RuleId = decision.RuleId,
                Reason = "Blocked by AgentGuard: waiting for approval in AgentGuard. Retry after it is approved.",
                EventId = e.Id,
                ApprovalId = approval.Id,
            };
        }

        var answer = await _approvals.WaitAsync(approval.Id, ct);
        var final = Allowed(answer, decision.OnTimeout);
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
                "killswitch" => "Blocked by AgentGuard: the kill switch is engaged.",
                _ => final ? "Approval timed out; allowed by policy." : $"Blocked by AgentGuard: no approval within {timeout} seconds.",
            },
            EventId = e.Id,
            ApprovalId = approval.Id,
        };
    }

    private static bool Allowed(string answer, Verdict onTimeout) => answer switch
    {
        "allow_once" or "allow_always" => true,
        "timeout" => onTimeout == Verdict.Allow,
        _ => false,
    };

    private async Task ExpireLaterAsync(string approvalId, TimeSpan after)
    {
        try
        {
            await Task.Delay(after);
            await ResolveAsync(approvalId, "timeout", "timeout");
        }
        catch (Exception ex) { _log.LogWarning(ex, "Failed to expire approval {Id}.", approvalId); }
    }

    /// <summary>
    /// Closes an approval (from a person, a timeout or the kill switch), adds the allow rule for "allow always",
    /// and records the outcome. Returns null when the approval is unknown or already closed.
    /// </summary>
    public async Task<ApprovalRecord?> ResolveAsync(string approvalId, string decision, string decidedBy)
    {
        var closed = _approvals.Resolve(approvalId, decision, decidedBy);
        if (closed is null) return null;
        if (!_context.TryRemove(approvalId, out var ctx)) return closed;

        var final = Allowed(decision, ctx.Decision.OnTimeout);
        string? addedRule = null;
        if (decision == "allow_always")
        {
            try { addedRule = _policy.AddAllowRule(ctx.Request.AgentId, ctx.Request.Action, ctx.Request.Target, decidedBy); }
            catch (Exception ex) { _log.LogError(ex, "Could not add the allow rule for approval {Id}.", approvalId); }
        }

        await _pipeline.RecordAsync(new EventInput
        {
            AgentId = ctx.Request.AgentId,
            AgentName = closed.AgentName,
            Pid = ctx.Request.Pid,
            Action = Actions.ApprovalDecided,
            Target = closed.Target,
            Details = new()
            {
                ["approvalId"] = approvalId,
                ["eventId"] = ctx.EventId,
                ["requestedAction"] = ctx.Request.Action,
                ["decision"] = decision,
                ["decidedBy"] = decidedBy,
                ["addedRule"] = addedRule,
            },
            Source = EventSources.System,
        }, new PolicyDecision(final ? Verdict.Allow : Verdict.Block, final ? Verdict.Allow : Verdict.Block, ctx.Decision.RuleId,
            ctx.Decision.Severity, false, "", 0, Verdict.Block), enforced: true);
        return closed;
    }

    /// <summary>Denies every open approval (the kill switch was engaged).</summary>
    public async Task<int> DenyAllPendingAsync(string decidedBy)
    {
        var n = 0;
        foreach (var id in _approvals.PendingIds)
            if (await ResolveAsync(id, "killswitch", decidedBy) is not null) n++;
        return n;
    }
}
