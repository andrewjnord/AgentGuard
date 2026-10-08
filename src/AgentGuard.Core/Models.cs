using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentGuard.Core;

public enum Verdict { Allow, Log, Ask, Block }

public enum Severity { Info, Low, Medium, High, Critical }

public enum PolicyMode { Monitor, Enforce, Strict }

/// <summary>Well-known action names. The set is open; rules may match any string.</summary>
public static class Actions
{
    public const string ProcessStart = "process.start";
    public const string ShellExec = "shell.exec";
    public const string FileRead = "file.read";
    public const string FileWrite = "file.write";
    public const string FileDelete = "file.delete";
    public const string NetConnect = "net.connect";
    public const string McpCall = "mcp.call";
    public const string AgentDiscovered = "agent.discovered";
    public const string AgentExited = "agent.exited";
    public const string ApprovalDecided = "approval.decided";
    public const string PolicyChanged = "policy.changed";
    public const string KillSwitch = "killswitch";
    public const string System = "system";
}

public static class AgentKinds
{
    public const string Cli = "cli";
    public const string Desktop = "desktop";
    public const string IdeExtension = "ide-extension";
    public const string LocalModel = "local-model";
    public const string McpServer = "mcp-server";
    public const string Unknown = "unknown";
}

public static class EventSources
{
    public const string Hook = "hook";
    public const string McpProxy = "mcp-proxy";
    public const string Etw = "etw";
    public const string Discovery = "discovery";
    public const string System = "system";
    public const string Demo = "demo";
}

public sealed class AgentEvent
{
    public long Id { get; set; }
    public DateTimeOffset Ts { get; set; } = DateTimeOffset.UtcNow;
    public string AgentId { get; set; } = "";
    public string AgentName { get; set; } = "";
    public int? Pid { get; set; }
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
    public Dictionary<string, object?> Details { get; set; } = new();
    public Verdict Verdict { get; set; } = Verdict.Log;
    public string? RuleId { get; set; }
    public Severity Severity { get; set; } = Severity.Info;
    public string Source { get; set; } = EventSources.System;
    public bool Enforced { get; set; }
    public string Hash { get; set; } = "";
    [JsonIgnore] public string PrevHash { get; set; } = "";
}

public sealed class AgentRecord
{
    public string Id { get; set; } = "";
    public string Kind { get; set; } = AgentKinds.Unknown;
    public string Name { get; set; } = "";
    public string? ExePath { get; set; }
    public string? Publisher { get; set; }
    public bool? SignerValid { get; set; }
    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;
    public string Trust { get; set; } = "unknown";
    public bool NetworkBlocked { get; set; }
}

public sealed class McpServerRecord
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Client { get; set; } = "";
    public string ConfigPath { get; set; } = "";
    /// <summary>JSON path segments from the config root to the server entry.</summary>
    public List<string> JsonPath { get; set; } = new();
    public string Scope { get; set; } = "user";
    public string Transport { get; set; } = "stdio";
    public string? Command { get; set; }
    public List<string> Args { get; set; } = new();
    public string? Url { get; set; }
    public bool Proxied { get; set; }
    /// <summary>Upstream URL for an HTTP server that AgentGuard has redirected to its local forwarder.</summary>
    public string? UpstreamUrl { get; set; }
    public DateTimeOffset? LastCallAt { get; set; }
    public string AgentId => "mcp:" + Name;
}

public sealed class AlertRecord
{
    public long Id { get; set; }
    public long EventId { get; set; }
    public DateTimeOffset Ts { get; set; }
    public Severity Severity { get; set; }
    public string Status { get; set; } = "open";
    public string Title { get; set; } = "";
    public string AgentId { get; set; } = "";
    public string AgentName { get; set; } = "";
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
    public string? RuleId { get; set; }
}

public sealed class ApprovalRecord
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n");
    public long EventId { get; set; }
    public DateTimeOffset RequestedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; }
    public string AgentId { get; set; } = "";
    public string AgentName { get; set; } = "";
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
    public Dictionary<string, object?> Details { get; set; } = new();
    public string? RuleId { get; set; }
    public string Status { get; set; } = "pending";
    public string? Decision { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
    public string? DecidedBy { get; set; }
}

public sealed class DecideRequest
{
    public string AgentId { get; set; } = "";
    public string? AgentName { get; set; }
    public int? Pid { get; set; }
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
    public Dictionary<string, object?>? Details { get; set; }
    public string Source { get; set; } = EventSources.Hook;
    public string? UserProfile { get; set; }
    public string? Cwd { get; set; }
    public bool? Wait { get; set; }
}

public sealed class DecideResponse
{
    /// <summary>Final verdict: "allow" or "block".</summary>
    public string Verdict { get; set; } = "allow";
    public Verdict PolicyVerdict { get; set; }
    public string? RuleId { get; set; }
    public string Reason { get; set; } = "";
    public long EventId { get; set; }
    public string? ApprovalId { get; set; }
    [JsonIgnore] public bool Allowed => Verdict == "allow";
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = Create(false);
    public static readonly JsonSerializerOptions Indented = Create(true);

    private static JsonSerializerOptions Create(bool indented)
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = indented };
        o.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return o;
    }

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);

    /// <summary>Converts a details dictionary that may hold JsonElements into plain CLR values.</summary>
    public static Dictionary<string, object?> Normalize(Dictionary<string, object?>? details)
    {
        var result = new Dictionary<string, object?>();
        if (details is null) return result;
        foreach (var (k, v) in details) result[k] = Normalize(v);
        return result;
    }

    public static object? Normalize(object? v) => v switch
    {
        JsonElement e => FromElement(e),
        _ => v,
    };

    public static object? FromElement(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.TryGetInt64(out var l) ? (object)l : e.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null or JsonValueKind.Undefined => null,
        JsonValueKind.Array => e.EnumerateArray().Select(FromElement).ToList(),
        JsonValueKind.Object => e.EnumerateObject().ToDictionary(p => p.Name, p => FromElement(p.Value)),
        _ => e.ToString(),
    };
}
