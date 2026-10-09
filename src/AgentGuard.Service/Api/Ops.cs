using AgentGuard.Core;
using AgentGuard.Core.Storage;
using AgentGuard.Service.Services;

namespace AgentGuard.Service.Api;

/// <summary>Management operations that touch several services: process control, the kill switch and integrity checks.</summary>
public sealed class Ops
{
    private readonly AgentRegistry _agents;
    private readonly EnforcementService _enforcement;
    private readonly KillSwitch _killSwitch;
    private readonly DecisionService _decisions;
    private readonly EventPipeline _pipeline;
    private readonly EventStore _store;
    private readonly StatusService _status;
    private readonly EventBus _bus;
    private readonly SemaphoreSlim _killGate = new(1, 1);

    public Ops(AgentRegistry agents, EnforcementService enforcement, KillSwitch killSwitch, DecisionService decisions,
        EventPipeline pipeline, EventStore store, StatusService status, EventBus bus)
    {
        _agents = agents;
        _enforcement = enforcement;
        _killSwitch = killSwitch;
        _decisions = decisions;
        _pipeline = pipeline;
        _store = store;
        _status = status;
        _bus = bus;
    }

    public async Task<IResult> ProcessAction(string id, string action, string actor)
    {
        var a = _agents.Get(id);
        if (a is null || id == "agentguard") return Endpoints.Error(404, $"Agent {id} not found.");
        EnforcementService.Outcome outcome;
        try
        {
            outcome = action switch
            {
                "suspend" => _enforcement.SuspendAgent(id),
                "resume" => _enforcement.ResumeAgent(id),
                _ => _enforcement.TerminateAgent(id),
            };
        }
        catch (EnforcementUnavailableException ex) { return Endpoints.Error(409, ex.Message); }

        var verb = action switch { "suspend" => "Suspended", "resume" => "Resumed", _ => "Terminated" };
        await _pipeline.RecordAsync(Endpoints.SystemInput(a, $"{verb} {a.Name}", new()
        {
            ["operation"] = action,
            ["affected"] = outcome.Affected,
            ["skipped"] = outcome.Refused.Count > 0 ? outcome.Refused.Take(20).ToList() : null,
            ["by"] = actor,
        }, action == "terminate" ? Actions.AgentExited : Actions.System), Endpoints.LogDecision(Severity.Medium), enforced: outcome.Affected > 0);
        _bus.Publish("agentChanged", id);
        _bus.Publish("status", "");
        return Results.Ok(new { affected = outcome.Affected });
    }

    public async Task<IResult> KillSwitch(string? action, string actor)
    {
        if (action is not ("engage" or "release" or "terminate")) return Endpoints.Error(400, "action must be engage, release or terminate.");
        await _killGate.WaitAsync();
        try
        {
            var affected = 0;
            var denied = 0;
            switch (action)
            {
                case "engage":
                    _killSwitch.Engage();
                    denied = await _decisions.DenyAllPendingAsync("killswitch");
                    if (_enforcement.ProcessControl) affected = _enforcement.SuspendAll().Affected;
                    break;
                case "release":
                    if (_enforcement.ProcessControl) affected = _enforcement.ResumeAll().Affected;
                    _killSwitch.Release();
                    break;
                case "terminate":
                    _killSwitch.Engage();
                    denied = await _decisions.DenyAllPendingAsync("killswitch");
                    if (_enforcement.ProcessControl) affected = _enforcement.TerminateAll().Affected;
                    break;
            }
            await _pipeline.SystemEventAsync(Actions.KillSwitch, action, new()
            {
                ["action"] = action,
                ["by"] = actor,
                ["processesAffected"] = affected,
                ["approvalsDenied"] = denied,
                ["processControl"] = _enforcement.ProcessControl,
            }, action == "release" ? Severity.Medium : Severity.High);
            foreach (var agent in _agents.All()) _bus.Publish("agentChanged", agent.Id);
            _bus.Publish("status", "");
            return Results.Ok(_status.Status());
        }
        finally { _killGate.Release(); }
    }

    public async Task<IResult> VerifyIntegrityAsync()
    {
        var r = await Task.Run(_store.VerifyIntegrity);
        _status.LastIntegrityCheck = r.VerifiedAt;
        _status.LastIntegrityOk = r.Ok;
        if (!r.Ok)
        {
            await _pipeline.RecordAsync(new EventInput
            {
                AgentId = "agentguard",
                AgentName = "AgentGuard",
                Action = Actions.System,
                Target = $"Audit log integrity check failed at event {r.FirstBadId}",
                Details = new() { ["checked"] = r.Checked, ["firstBadId"] = r.FirstBadId },
                Source = EventSources.System,
            }, Endpoints.LogDecision(Severity.Critical, alert: true), enforced: false);
        }
        _bus.Publish("status", "");
        return Results.Ok(new { ok = r.Ok, @checked = r.Checked, firstBadId = r.FirstBadId, verifiedAt = r.VerifiedAt });
    }
}
