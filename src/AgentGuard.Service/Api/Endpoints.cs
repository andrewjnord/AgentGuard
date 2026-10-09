using System.Globalization;
using System.Text.RegularExpressions;
using AgentGuard.Core;
using AgentGuard.Core.Export;
using AgentGuard.Core.Policy;
using AgentGuard.Core.Storage;
using AgentGuard.Service.Services;

namespace AgentGuard.Service.Api;

public sealed record ModeBody(string? Mode);
public sealed record TrustBody(string? Trust);
public sealed record NetworkBody(bool? Blocked);
public sealed record KillSwitchBody(string? Action);
public sealed record ProxyBody(bool? Enabled);
public sealed record AlertStatusBody(string? Status);
public sealed record ApprovalDecisionBody(string? Decision);
public sealed record YamlBody(string? Yaml);
public sealed record ExportTargetBody(string? Target);

/// <summary>The local API (docs/api.md).</summary>
public static partial class Endpoints
{
    public const string ActorHeader = "X-AgentGuard-Actor";

    [GeneratedRegex("^[A-Za-z0-9._:@/+-]{1,128}$")]
    private static partial Regex AgentIdPattern();

    [GeneratedRegex("^[a-z0-9-]{1,32}$")]
    private static partial Regex ActorPattern();

    public static IResult Error(int status, string message, object? extra = null) =>
        extra is null ? Results.Json(new { error = message }, ApiJson.Options, statusCode: status)
                      : Results.Json(new { error = message, details = extra }, ApiJson.Options, statusCode: status);

    /// <summary>Who made a management change, for the audit trail: "tray", "cli" or (default) "dashboard".</summary>
    public static string Actor(HttpContext ctx)
    {
        var a = ctx.Request.Headers[ActorHeader].ToString().ToLowerInvariant();
        return ActorPattern().IsMatch(a) ? a : "dashboard";
    }

    public static void MapAgentGuardApi(this WebApplication app)
    {
        var api = app.MapGroup("/api/v1");

        api.MapGet("/health", () => Results.Ok(new { ok = true, version = StatusService.Version }));
        api.MapGet("/status", (StatusService s) => Results.Ok(s.Status()));
        api.MapPut("/mode", SetMode);
        api.MapGet("/stats/activity", Activity);

        api.MapGet("/agents", (StatusService s) => Results.Ok(s.Agents()));
        api.MapGet("/agents/{id}", (string id, StatusService s) => s.Agent(id) is { } a ? Results.Ok(a) : Error(404, $"Agent {id} not found."));
        api.MapPut("/agents/{id}/trust", SetTrust);
        api.MapPut("/agents/{id}/network", SetNetwork);
        api.MapPost("/agents/{id}/suspend", (string id, HttpContext ctx, Ops ops) => ops.ProcessAction(id, "suspend", Actor(ctx)));
        api.MapPost("/agents/{id}/resume", (string id, HttpContext ctx, Ops ops) => ops.ProcessAction(id, "resume", Actor(ctx)));
        api.MapPost("/agents/{id}/terminate", (string id, HttpContext ctx, Ops ops) => ops.ProcessAction(id, "terminate", Actor(ctx)));
        api.MapPost("/killswitch", (KillSwitchBody? body, HttpContext ctx, Ops ops) => ops.KillSwitch(body?.Action, Actor(ctx)));

        api.MapGet("/mcp", (McpManager m) => Results.Ok(m.List().Select(StatusService.ToDto)));
        api.MapPut("/mcp/{id}/proxy", SetProxy);
        api.MapPost("/mcp/rescan", (McpManager m) => Results.Ok(m.Rescan().Select(StatusService.ToDto)));

        api.MapGet("/events", QueryEvents);
        api.MapGet("/events/{id:long}", (long id, EventStore store) => store.GetEvent(id) is { } e ? Results.Ok(e) : Error(404, $"Event {id} not found."));

        api.MapGet("/alerts", (string? status, EventStore store) =>
            status is null or "open" or "acked" or "closed" ? Results.Ok(store.ListAlerts(status)) : Error(400, "status must be open, acked or closed."));
        api.MapPut("/alerts/{id:long}", SetAlertStatus);

        api.MapGet("/approvals", (string? status, EventStore store) =>
            status is null or "pending" or "allowed" or "denied" or "expired" ? Results.Ok(store.ListApprovals(status)) : Error(400, "status must be pending, allowed, denied or expired."));
        api.MapPost("/approvals/{id}", DecideApproval);

        api.MapGet("/policy", (PolicyManager p) => Results.Ok(PolicyInfo(p.Current, p.Mode)));
        api.MapPost("/policy/validate", (YamlBody? body, PolicyManager p) => Results.Ok(Validation(p.Validate(body?.Yaml ?? ""))));
        api.MapPut("/policy", ApplyPolicy);
        api.MapGet("/policy/history", (EventStore store) =>
            Results.Ok(store.PolicyHistory().Select(v => new { version = v.Version, appliedAt = v.AppliedAt, appliedBy = v.AppliedBy, ruleCount = v.RuleCount })));
        api.MapGet("/policy/history/{version:int}", (int version, EventStore store, AgentGuardOptions o) =>
            store.GetPolicy(version) is { } v ? Results.Ok(PolicyInfo(v, ModeOf(v.Yaml, o.DataDir))) : Error(404, $"Policy version {version} not found."));

        api.MapGet("/settings", (SettingsManager s) => Results.Ok(s.Current.Masked()));
        api.MapPut("/settings", SaveSettings);
        api.MapPost("/settings/test-export", TestExport);

        api.MapPost("/integrity/verify", (Ops ops) => ops.VerifyIntegrityAsync());
        api.MapGet("/export", ExportEndpoint.HandleAsync);
        api.MapGet("/stream", StreamEndpoint.HandleAsync);
        api.MapPost("/decide", Decide);
    }

    // ------------------------------------------------------------------ status and mode

    private static async Task<IResult> SetMode(ModeBody? body, HttpContext ctx, PolicyManager policy, EventPipeline pipeline, StatusService status, EventBus bus)
    {
        if (!Enum.TryParse<PolicyMode>(body?.Mode, ignoreCase: true, out var mode) || !Enum.IsDefined(mode) || int.TryParse(body?.Mode, out _))
            return Error(400, "mode must be monitor, enforce or strict.");
        var before = policy.Mode;
        try { policy.SetMode(mode, Actor(ctx)); }
        catch (InvalidOperationException ex) { return Error(409, ex.Message); }
        if (before != mode)
            await pipeline.SystemEventAsync(Actions.PolicyChanged, $"Mode changed to {Lower(mode)}",
                new() { ["from"] = Lower(before), ["to"] = Lower(mode), ["by"] = Actor(ctx), ["version"] = policy.Current.Version }, Severity.Medium);
        bus.Publish("status", "");
        return Results.Ok(status.Status());
    }

    private static IResult Activity(int? hours, EventStore store)
    {
        var h = Math.Clamp(hours ?? 24, 1, 24 * 31);
        var now = DateTimeOffset.UtcNow;
        var buckets = store.Activity(now, h).Select(b => new { ts = b.Ts, total = b.Total, blocked = b.Blocked, asked = b.Asked });
        var top = store.AgentActivity(now.AddHours(-h)).Where(a => a.AgentId != "agentguard")
            .OrderByDescending(a => a.Total).Take(8)
            .Select(a => new { agentId = a.AgentId, agentName = a.AgentName, total = a.Total, blocked = a.Blocked });
        return Results.Ok(new { buckets, topAgents = top });
    }

    // ------------------------------------------------------------------ agents

    private static async Task<IResult> SetTrust(string id, TrustBody? body, HttpContext ctx, AgentRegistry agents, StatusService status, EventPipeline pipeline, EventBus bus)
    {
        if (body?.Trust is not ("unknown" or "allowed" or "blocked")) return Error(400, "trust must be unknown, allowed or blocked.");
        var a = agents.Get(id);
        if (a is null || id == "agentguard") return Error(404, $"Agent {id} not found.");
        var before = a.Trust;
        agents.SetTrust(id, body.Trust);
        if (before != body.Trust)
            await pipeline.RecordAsync(SystemInput(a, $"Trust for {a.Name} set to {body.Trust}", new() { ["from"] = before, ["to"] = body.Trust, ["by"] = Actor(ctx) }), LogDecision(Severity.Low), false);
        bus.Publish("agentChanged", id);
        return Results.Ok(status.Agent(id));
    }

    private static async Task<IResult> SetNetwork(string id, NetworkBody? body, HttpContext ctx, EnforcementService enforcement, AgentRegistry agents, StatusService status, EventPipeline pipeline, EventBus bus)
    {
        if (body?.Blocked is not { } blocked) return Error(400, "blocked (true or false) is required.");
        var a = agents.Get(id);
        if (a is null || id == "agentguard") return Error(404, $"Agent {id} not found.");
        try { enforcement.SetNetworkBlocked(id, blocked); }
        catch (EnforcementUnavailableException ex) { return Error(409, ex.Message); }
        catch (EnforcementRefusedException ex) { return Error(409, ex.Message); }
        catch (Exception ex) { return Error(500, "The firewall change failed: " + ex.Message); }
        await pipeline.RecordAsync(SystemInput(a, $"{(blocked ? "Blocked" : "Unblocked")} network for {a.Name}",
            new() { ["blocked"] = blocked, ["firewallGroup"] = "AgentGuard", ["by"] = Actor(ctx) }), LogDecision(Severity.Medium), true);
        bus.Publish("agentChanged", id);
        return Results.Ok(status.Agent(id));
    }

    // ------------------------------------------------------------------ MCP

    private static IResult SetProxy(string id, ProxyBody? body, McpManager mcp)
    {
        if (body?.Enabled is not { } enabled) return Error(400, "enabled (true or false) is required.");
        try { return Results.Ok(StatusService.ToDto(mcp.SetProxied(id, enabled))); }
        catch (KeyNotFoundException ex) { return Error(404, ex.Message); }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return Error(409, ex.Message);
        }
    }

    // ------------------------------------------------------------------ events and alerts

    private static IResult QueryEvents(HttpContext ctx, EventStore store)
    {
        var q = ctx.Request.Query;
        var f = new EventFilter
        {
            AgentId = Empty(q["agentId"]),
            Action = Empty(q["action"]),
            Source = Empty(q["source"]),
            Query = Empty(q["q"]),
        };
        if (Empty(q["verdict"]) is { } v)
        {
            if (!TryEnum<Verdict>(v, out var verdict)) return Error(400, "verdict must be allow, log, ask or block.");
            f.Verdict = verdict;
        }
        if (Empty(q["severity"]) is { } s)
        {
            if (!TryEnum<Severity>(s, out var sev)) return Error(400, "severity must be info, low, medium, high or critical.");
            f.Severity = sev;
        }
        if (!TryTime(q["from"], out var from) || !TryTime(q["to"], out var to)) return Error(400, "from and to must be ISO-8601 timestamps.");
        f.From = from;
        f.To = to;
        if (Empty(q["before"]) is { } b)
        {
            if (!long.TryParse(b, out var before)) return Error(400, "before must be an event id.");
            f.Before = before;
        }
        var limit = 100;
        if (Empty(q["limit"]) is { } l && (!int.TryParse(l, out limit) || limit < 1)) return Error(400, "limit must be a positive number.");
        f.Limit = Math.Min(limit, 1000);
        var items = store.QueryEvents(f);
        return Results.Ok(new { items, nextBefore = items.Count == f.Limit ? items[^1].Id : (long?)null });
    }

    private static IResult SetAlertStatus(long id, AlertStatusBody? body, EventStore store, EventBus bus)
    {
        if (body?.Status is not ("open" or "acked" or "closed")) return Error(400, "status must be open, acked or closed.");
        var a = store.SetAlertStatus(id, body.Status);
        if (a is null) return Error(404, $"Alert {id} not found.");
        bus.Publish("alert", a);
        bus.Publish("status", "");
        return Results.Ok(a);
    }

    // ------------------------------------------------------------------ approvals and decisions

    private static async Task<IResult> DecideApproval(string id, ApprovalDecisionBody? body, HttpContext ctx, DecisionService decisions, EventStore store, EventBus bus)
    {
        if (body?.Decision is not ("allow_once" or "allow_always" or "deny")) return Error(400, "decision must be allow_once, allow_always or deny.");
        var closed = await decisions.ResolveAsync(id, body.Decision, Actor(ctx));
        if (closed is not null)
        {
            bus.Publish("status", "");
            return Results.Ok(closed);
        }
        return store.GetApproval(id) is { } existing
            ? Error(409, $"Approval is already {existing.Status}.", existing)
            : Error(404, $"Approval {id} not found.");
    }

    private static async Task<IResult> Decide(DecideRequest? req, HttpContext ctx, DecisionService decisions)
    {
        if (req is null) return Error(400, "A JSON body is required.");
        if (string.IsNullOrWhiteSpace(req.AgentId) || !AgentIdPattern().IsMatch(req.AgentId)) return Error(400, "agentId is required (letters, digits and . _ : @ / + -).");
        if (req.AgentId.Equals("agentguard", StringComparison.OrdinalIgnoreCase)) return Error(400, "agentId 'agentguard' is reserved.");
        if (string.IsNullOrWhiteSpace(req.Action) || req.Action.Length > 64) return Error(400, "action is required (at most 64 characters).");
        if (req.Target is null || req.Target.Length > 32_768) return Error(400, "target is required (at most 32768 characters).");
        if (req.Source is not (EventSources.Hook or EventSources.McpProxy)) return Error(400, "source must be hook or mcp-proxy.");
        if (req.AgentName is { Length: > 200 }) req.AgentName = req.AgentName[..200];
        try
        {
            var resp = await decisions.DecideAsync(req, ctx.RequestAborted);
            return Results.Ok(new
            {
                verdict = resp.Verdict,
                policyVerdict = resp.PolicyVerdict,
                ruleId = resp.RuleId,
                reason = resp.Reason,
                eventId = resp.EventId,
                approvalId = resp.ApprovalId,
            });
        }
        catch (OperationCanceledException) when (ctx.RequestAborted.IsCancellationRequested)
        {
            return Results.Empty; // caller went away while waiting for an approval
        }
    }

    // ------------------------------------------------------------------ policy

    private static async Task<IResult> ApplyPolicy(YamlBody? body, HttpContext ctx, PolicyManager policy, EventPipeline pipeline, EventBus bus)
    {
        var yaml = body?.Yaml;
        if (string.IsNullOrWhiteSpace(yaml)) return Results.Json(Validation(policy.Validate("")), ApiJson.Options, statusCode: 400);
        var before = policy.Current;
        var (version, result) = policy.Apply(yaml, Actor(ctx));
        if (version is null) return Results.Json(Validation(result), ApiJson.Options, statusCode: 400);
        if (version.Version != before.Version)
            await pipeline.SystemEventAsync(Actions.PolicyChanged, $"Policy v{version.Version} applied",
                new() { ["version"] = version.Version, ["previousVersion"] = before.Version, ["ruleCount"] = version.RuleCount, ["by"] = version.AppliedBy, ["mode"] = Lower(policy.Mode) }, Severity.Medium);
        bus.Publish("status", "");
        return Results.Ok(PolicyInfo(version, policy.Mode));
    }

    public static object PolicyInfo(PolicyVersion v, PolicyMode mode) => new
    {
        yaml = v.Yaml,
        version = v.Version,
        appliedAt = v.AppliedAt,
        appliedBy = v.AppliedBy,
        ruleCount = v.RuleCount,
        mode = Lower(mode),
    };

    public static object Validation(PolicyParser.Result r) => new
    {
        ok = r.Ok,
        ruleCount = r.Document?.Rules.Count ?? 0,
        errors = r.Errors.Select(e => new { line = e.Line, column = e.Column, message = e.Message }),
    };

    private static PolicyMode ModeOf(string yaml, string baseDir)
    {
        var r = PolicyParser.Parse(yaml, baseDir);
        return r.Document?.Mode ?? PolicyMode.Enforce;
    }

    // ------------------------------------------------------------------ settings

    private static async Task<IResult> SaveSettings(AgentGuardSettings? body, HttpContext ctx, SettingsManager settings, EventPipeline pipeline)
    {
        if (body is null) return Error(400, "A settings object is required.");
        var (saved, errors) = settings.Update(body);
        if (saved is null) return Error(400, errors[0], errors);
        await pipeline.SystemEventAsync(Actions.System, "Settings changed", new() { ["by"] = Actor(ctx) }, Severity.Low);
        return Results.Ok(saved.Masked());
    }

    private static async Task<IResult> TestExport(ExportTargetBody? body, SettingsManager settings, CancellationToken ct)
    {
        var s = settings.Current;
        var e = new AgentEvent
        {
            Id = 0,
            AgentId = "agentguard",
            AgentName = "AgentGuard",
            Action = Actions.System,
            Target = "AgentGuard export test",
            Details = new() { ["test"] = true },
            Verdict = Verdict.Log,
            Severity = Severity.Info,
            Source = EventSources.System,
            Hash = "test",
        };
        try
        {
            switch (body?.Target)
            {
                case "splunk":
                    if (!Uri.TryCreate(s.Exports.Splunk.Url, UriKind.Absolute, out _)) return Results.Ok(new { ok = false, message = "Set a valid Splunk HEC URL and save first." });
                    using (var x = new SplunkHecExporter(s.Exports.Splunk, Environment.MachineName, StatusService.Version))
                        await x.ExportAsync(new[] { e }, ct);
                    return Results.Ok(new { ok = true, message = $"Splunk accepted a test event at {s.Exports.Splunk.Url}." });
                case "syslog":
                    if (string.IsNullOrWhiteSpace(s.Exports.Syslog.Host)) return Results.Ok(new { ok = false, message = "Set a syslog host and save first." });
                    await new SyslogExporter(s.Exports.Syslog, Environment.MachineName, StatusService.Version).ExportAsync(new[] { e }, ct);
                    return Results.Ok(new
                    {
                        ok = true,
                        message = s.Exports.Syslog.Protocol == "udp"
                            ? $"Sent a test message to {s.Exports.Syslog.Host}:{s.Exports.Syslog.Port} over UDP (delivery is not confirmed for UDP)."
                            : $"Delivered a test message to {s.Exports.Syslog.Host}:{s.Exports.Syslog.Port} over TCP.",
                    });
                case "jsonFile":
                    if (string.IsNullOrWhiteSpace(s.Exports.JsonFile.Directory)) return Results.Ok(new { ok = false, message = "Set an export directory and save first." });
                    await new JsonFileExporter(s.Exports.JsonFile.Directory, Environment.MachineName, StatusService.Version).ExportAsync(new[] { e }, ct);
                    return Results.Ok(new { ok = true, message = $"Wrote a test event to {s.Exports.JsonFile.Directory}." });
                default:
                    return Error(400, "target must be splunk, syslog or jsonFile.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            return Results.Ok(new { ok = false, message = ex.Message });
        }
    }

    // ------------------------------------------------------------------ helpers

    public static string Lower<T>(T value) where T : Enum => value.ToString().ToLowerInvariant();

    private static string? Empty(Microsoft.Extensions.Primitives.StringValues v) => string.IsNullOrWhiteSpace(v) ? null : v.ToString();

    private static bool TryEnum<T>(string s, out T value) where T : struct, Enum =>
        Enum.TryParse(s, true, out value) && Enum.IsDefined(value) && !int.TryParse(s, out _);

    private static bool TryTime(Microsoft.Extensions.Primitives.StringValues v, out DateTimeOffset? value)
    {
        value = null;
        if (string.IsNullOrWhiteSpace(v)) return true;
        if (!DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)) return false;
        value = t;
        return true;
    }

    internal static EventInput SystemInput(AgentRecord a, string target, Dictionary<string, object?> details, string action = Actions.System) => new()
    {
        AgentId = a.Id,
        AgentName = a.Name,
        Action = action,
        Target = target,
        Details = details,
        Source = EventSources.System,
    };

    internal static PolicyDecision LogDecision(Severity severity, bool alert = false) =>
        new(Verdict.Log, Verdict.Log, null, severity, alert, "", 0, Verdict.Block);
}
