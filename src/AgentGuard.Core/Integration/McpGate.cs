using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgentGuard.Core.Integration;

/// <summary>
/// Checks client-to-server MCP JSON-RPC messages before they reach a tool server. Every <c>tools/call</c> is turned into
/// an <c>mcp.call</c> decision plus derived file / network / shell checks from its arguments; anything else passes through.
/// Shared by the stdio proxy and the service's HTTP forwarder.
/// </summary>
public sealed class McpGate
{
    public delegate Task<DecideResponse> Decider(DecideRequest request, CancellationToken ct);

    /// <summary>What to do with a message: forward <see cref="Forward"/> (if not null) and/or send <see cref="Reply"/> back to the client.</summary>
    public sealed record Result(string? Forward, string? Reply, IReadOnlyList<CheckedCall> Calls);

    public sealed record CheckedCall(JsonNode? Id, string Tool, bool Allowed, string Reason, long? EventId);

    private readonly string _server;
    private readonly Decider _decide;
    private readonly bool _failOpen;

    public string? UserProfile { get; init; }
    public string? Cwd { get; init; }
    public int? Pid { get; init; }
    public string? ClientName { get; set; }
    public string Source { get; init; } = EventSources.McpProxy;

    public McpGate(string serverName, Decider decide, bool failOpen = false)
    {
        _server = serverName;
        _decide = decide;
        _failOpen = failOpen;
    }

    public string AgentId => "mcp:" + _server;

    public async Task<Result> CheckAsync(string json, CancellationToken ct = default)
    {
        JsonNode? root;
        try { root = JsonNode.Parse(json); }
        catch (JsonException) { return new Result(json, null, Array.Empty<CheckedCall>()); } // not ours to judge; the server will reject it

        if (root is JsonArray batch)
        {
            var forward = new JsonArray();
            var replies = new JsonArray();
            var calls = new List<CheckedCall>();
            foreach (var item in batch)
            {
                var (call, reply) = await CheckOneAsync(item, ct);
                if (call is not null) calls.Add(call);
                if (reply is not null) replies.Add(reply);
                else forward.Add(item?.DeepClone());
            }
            return new Result(forward.Count > 0 ? forward.ToJsonString() : null, replies.Count > 0 ? replies.ToJsonString() : null, calls);
        }

        var (single, singleReply) = await CheckOneAsync(root, ct);
        var list = single is null ? Array.Empty<CheckedCall>() : new[] { single };
        return singleReply is null ? new Result(json, null, list) : new Result(null, singleReply.ToJsonString(), list);
    }

    private async Task<(CheckedCall? Call, JsonNode? Reply)> CheckOneAsync(JsonNode? message, CancellationToken ct)
    {
        if (message is not JsonObject obj) return (null, null);
        RememberClient(obj);
        if (obj["method"]?.GetValueKind() != JsonValueKind.String || obj["method"]!.GetValue<string>() != "tools/call") return (null, null);

        var id = obj["id"]?.DeepClone();
        var p = obj["params"] as JsonObject;
        var tool = p?["name"]?.GetValueKind() == JsonValueKind.String ? p["name"]!.GetValue<string>() : "";
        var argsElement = p?["arguments"] is JsonObject a ? JsonSerializer.Deserialize<JsonElement>(a.ToJsonString()) : default;

        foreach (var request in BuildRequests(tool, argsElement))
        {
            DecideResponse verdict;
            try { verdict = await _decide(request, ct); }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or AgentGuardApiException or IOException && !ct.IsCancellationRequested)
            {
                if (_failOpen) return (new CheckedCall(id, tool, true, "AgentGuard unreachable; allowed (fail-open).", null), null);
                var why = "Blocked by AgentGuard: the AgentGuard service is not reachable, so tool calls are blocked (fail-closed).";
                return (new CheckedCall(id, tool, false, why, null), BlockedReply(id, why));
            }
            if (!verdict.Allowed)
                return (new CheckedCall(id, tool, false, verdict.Reason, verdict.EventId), BlockedReply(id, verdict.Reason));
        }
        return (new CheckedCall(id, tool, true, "allowed", null), null);
    }

    /// <summary>The <c>mcp.call</c> check first, then checks derived from path, URL and command arguments.</summary>
    public List<DecideRequest> BuildRequests(string tool, JsonElement arguments)
    {
        var args = arguments.ValueKind == JsonValueKind.Object ? Json.FromElement(arguments) : null;
        var list = new List<DecideRequest>
        {
            Make(Actions.McpCall, $"{_server}/{tool}", new() { ["server"] = _server, ["tool"] = tool, ["arguments"] = args, ["client"] = ClientName }),
        };
        foreach (var d in McpArgumentInspector.Derive(tool, arguments))
            list.Add(Make(d.Action, d.Target, new() { ["server"] = _server, ["tool"] = tool, ["derivedFrom"] = "mcp.call", ["client"] = ClientName }));
        return list;
    }

    private DecideRequest Make(string action, string target, Dictionary<string, object?> details) => new()
    {
        AgentId = AgentId,
        AgentName = "MCP: " + _server,
        Pid = Pid,
        Action = action,
        Target = target,
        Details = details,
        Source = Source,
        UserProfile = UserProfile,
        Cwd = Cwd,
    };

    private void RememberClient(JsonObject obj)
    {
        if (obj["method"]?.GetValueKind() == JsonValueKind.String && obj["method"]!.GetValue<string>() == "initialize"
            && obj["params"]?["clientInfo"]?["name"] is JsonValue v && v.GetValueKind() == JsonValueKind.String)
            ClientName = v.GetValue<string>();
    }

    /// <summary>A tool result with <c>isError</c>, so the model sees why instead of a protocol failure.</summary>
    public static JsonObject BlockedReply(JsonNode? id, string reason) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["result"] = new JsonObject
        {
            ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = reason }),
            ["isError"] = true,
        },
    };
}
