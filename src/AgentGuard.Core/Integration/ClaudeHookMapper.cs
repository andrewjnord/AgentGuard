using System.Text.Json;

namespace AgentGuard.Core.Integration;

/// <summary>Maps a Claude Code PreToolUse hook payload to AgentGuard decide requests.</summary>
public static class ClaudeHookMapper
{
    public const string AgentId = "claude-code";
    public const string AgentName = "Claude Code";

    public static List<DecideRequest> Map(JsonElement input, string? userProfile, int? pid = null)
    {
        var tool = Str(input, "tool_name") ?? "";
        var cwd = Str(input, "cwd");
        var toolInput = input.TryGetProperty("tool_input", out var ti) && ti.ValueKind == JsonValueKind.Object ? ti : default;
        var details = new Dictionary<string, object?>
        {
            ["tool"] = tool,
            ["sessionId"] = Str(input, "session_id"),
            ["toolUseId"] = Str(input, "tool_use_id"),
            ["permissionMode"] = Str(input, "permission_mode"),
        };

        DecideRequest Make(string action, string target, Dictionary<string, object?>? extra = null)
        {
            var d = new Dictionary<string, object?>(details);
            if (extra is not null) foreach (var (k, v) in extra) d[k] = v;
            return new DecideRequest
            {
                AgentId = AgentId,
                AgentName = AgentName,
                Pid = pid,
                Action = action,
                Target = target,
                Details = d,
                Source = EventSources.Hook,
                UserProfile = userProfile,
                Cwd = cwd,
            };
        }

        string? Arg(string name) => toolInput.ValueKind == JsonValueKind.Object ? Str(toolInput, name) : null;

        string Resolve(string? path)
        {
            if (string.IsNullOrEmpty(path)) return cwd ?? "";
            if (path.StartsWith("~/") || path.StartsWith("~\\")) return Path.Combine(userProfile ?? "", path[2..]);
            if (Path.IsPathRooted(path) || cwd is null) return path;
            return Path.GetFullPath(Path.Combine(cwd, path));
        }

        var requests = new List<DecideRequest>();
        switch (tool)
        {
            case "Bash":
            case "PowerShell":
                requests.Add(Make(Actions.ShellExec, Arg("command") ?? "", new() { ["description"] = Arg("description") }));
                break;
            case "Read":
                requests.Add(Make(Actions.FileRead, Resolve(Arg("file_path"))));
                break;
            case "Glob":
            case "Grep":
            case "LS":
                requests.Add(Make(Actions.FileRead, Resolve(Arg("path")), new() { ["pattern"] = Arg("pattern") }));
                break;
            case "Write":
            case "Edit":
            case "MultiEdit":
                requests.Add(Make(Actions.FileWrite, Resolve(Arg("file_path"))));
                break;
            case "NotebookEdit":
                requests.Add(Make(Actions.FileWrite, Resolve(Arg("notebook_path"))));
                break;
            case "WebFetch":
                requests.Add(Make(Actions.NetConnect, Arg("url") ?? "", new() { ["url"] = Arg("url") }));
                break;
            case "WebSearch":
                requests.Add(Make("web.search", Arg("query") ?? ""));
                break;
            default:
                if (tool.StartsWith("mcp__", StringComparison.Ordinal))
                {
                    var parts = tool.Split("__", 3);
                    var server = parts.Length > 1 ? parts[1] : "";
                    var name = parts.Length > 2 ? parts[2] : tool;
                    var args = toolInput.ValueKind == JsonValueKind.Object ? Json.FromElement(toolInput) : null;
                    requests.Add(Make(Actions.McpCall, $"{server}/{name}", new() { ["server"] = server, ["tool"] = name, ["arguments"] = args }));
                    foreach (var derived in McpArgumentInspector.Derive(name, toolInput))
                    {
                        var target = derived.Action.StartsWith("file.", StringComparison.Ordinal) ? Resolve(derived.Target) : derived.Target;
                        requests.Add(Make(derived.Action, target, new() { ["server"] = server, ["tool"] = name, ["derivedFrom"] = "mcp.call" }));
                    }
                }
                else
                {
                    requests.Add(Make("agent.tool", tool));
                }
                break;
        }
        return requests;
    }

    /// <summary>Builds the JSON written to stdout for Claude Code.</summary>
    public static string Output(bool allow, string reason) =>
        JsonSerializer.Serialize(new
        {
            hookSpecificOutput = new
            {
                hookEventName = "PreToolUse",
                permissionDecision = allow ? "allow" : "deny",
                permissionDecisionReason = reason,
            },
        });

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>Derives file, network and shell checks from MCP tool arguments so path and host rules also cover MCP servers.</summary>
public static class McpArgumentInspector
{
    private static readonly string[] PathKeys = { "path", "file_path", "filepath", "filename", "file", "source", "destination", "directory", "dir", "target_path" };
    private static readonly string[] UrlKeys = { "url", "uri", "endpoint" };
    private static readonly string[] CommandKeys = { "command", "cmd", "script" };

    public sealed record Derived(string Action, string Target);

    public static List<Derived> Derive(string toolName, JsonElement arguments)
    {
        var result = new List<Derived>();
        if (arguments.ValueKind != JsonValueKind.Object) return result;
        var t = toolName.ToLowerInvariant();
        var fileAction = t.Contains("delete") || t.Contains("remove") ? Actions.FileDelete
            : t.Contains("write") || t.Contains("edit") || t.Contains("create") || t.Contains("move") || t.Contains("update") || t.Contains("append") ? Actions.FileWrite
            : Actions.FileRead;

        foreach (var prop in arguments.EnumerateObject())
        {
            var key = prop.Name.ToLowerInvariant();
            var values = prop.Value.ValueKind switch
            {
                JsonValueKind.String => new[] { prop.Value.GetString()! },
                JsonValueKind.Array => prop.Value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToArray(),
                _ => Array.Empty<string>(),
            };
            foreach (var v in values.Where(v => v.Length > 0).Take(20))
            {
                if (PathKeys.Contains(key) || (key == "paths" && values.Length > 0)) result.Add(new Derived(fileAction, v));
                else if (UrlKeys.Contains(key)) result.Add(new Derived(Actions.NetConnect, v));
                else if (CommandKeys.Contains(key)) result.Add(new Derived(Actions.ShellExec, v));
            }
        }
        return result;
    }
}
