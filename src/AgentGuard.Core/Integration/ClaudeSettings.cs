using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgentGuard.Core.Integration;

/// <summary>Registers the AgentGuard PreToolUse hook in Claude Code settings files, and removes it again.</summary>
public static class ClaudeSettings
{
    public const string HookExeName = "agentguard-hook";

    /// <summary>
    /// Seconds Claude Code waits for the hook. A hook that times out lets the tool call through, so this must outlast the
    /// longest approval wait a policy can set (3600 s) plus the service round trip.
    /// </summary>
    public const int HookTimeoutSeconds = 3660;

    private static readonly JsonDocumentOptions ReadOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>Machine-wide drop-in that applies to every user and that user settings cannot disable.</summary>
    public static string ManagedDropInPath() => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClaudeCode", "managed-settings.d", "agentguard.json")
        : OperatingSystem.IsMacOS()
            ? "/Library/Application Support/ClaudeCode/managed-settings.d/agentguard.json"
            : "/etc/claude-code/managed-settings.d/agentguard.json";

    public static string UserSettingsPath(string? home = null) =>
        Path.Combine(home ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude", "settings.json");

    /// <summary>The command line Claude Code runs; quoted so paths with spaces (Program Files) work.</summary>
    public static string Command(string hookExePath) => "\"" + hookExePath + "\"";

    /// <summary>Adds (or replaces) the AgentGuard PreToolUse hook in a settings file, keeping everything else in it.</summary>
    public static void Install(string settingsPath, string hookExePath, int timeoutSeconds = HookTimeoutSeconds)
    {
        var root = Load(settingsPath);
        var hooks = root["hooks"] as JsonObject ?? new JsonObject();
        root["hooks"] = hooks;
        var pre = hooks["PreToolUse"] as JsonArray ?? new JsonArray();
        hooks["PreToolUse"] = pre;
        RemoveOurs(pre);
        pre.Add(new JsonObject
        {
            ["matcher"] = "*",
            ["hooks"] = new JsonArray(new JsonObject
            {
                ["type"] = "command",
                ["command"] = Command(hookExePath),
                ["timeout"] = timeoutSeconds,
            }),
        });
        Save(settingsPath, root);
    }

    /// <summary>Removes the AgentGuard hook. Returns false when it was not registered.</summary>
    public static bool Uninstall(string settingsPath)
    {
        if (!File.Exists(settingsPath)) return false;
        var root = Load(settingsPath);
        if (root["hooks"]?["PreToolUse"] is not JsonArray pre) return false;
        var removed = RemoveOurs(pre);
        if (pre.Count == 0) (root["hooks"] as JsonObject)!.Remove("PreToolUse");
        if (root["hooks"] is JsonObject { Count: 0 }) root.Remove("hooks");
        if (removed) Save(settingsPath, root);
        return removed;
    }

    public static bool IsInstalled(string settingsPath)
    {
        if (!File.Exists(settingsPath)) return false;
        try
        {
            return Load(settingsPath)["hooks"]?["PreToolUse"] is JsonArray pre
                   && pre.OfType<JsonObject>().Any(IsOurs);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { return false; }
    }

    private static bool RemoveOurs(JsonArray pre)
    {
        var ours = pre.OfType<JsonObject>().Where(IsOurs).ToList();
        foreach (var o in ours) pre.Remove(o);
        return ours.Count > 0;
    }

    private static bool IsOurs(JsonObject entry) =>
        entry["hooks"] is JsonArray list && list.OfType<JsonObject>().Any(h =>
            h["command"] is JsonValue v && v.GetValueKind() == JsonValueKind.String
            && v.GetValue<string>().Contains(HookExeName, StringComparison.OrdinalIgnoreCase));

    private static JsonObject Load(string path)
    {
        if (!File.Exists(path)) return new JsonObject();
        var text = File.ReadAllText(path);
        if (string.IsNullOrWhiteSpace(text)) return new JsonObject();
        return JsonNode.Parse(text, documentOptions: ReadOptions) as JsonObject
               ?? throw new InvalidOperationException($"{path} does not contain a JSON object.");
    }

    private static void Save(string path, JsonObject root)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        if (File.Exists(path))
        {
            var backup = path + ".agentguard.bak";
            if (!File.Exists(backup)) File.Copy(path, backup);
        }
        var tmp = path + ".agentguard.tmp";
        File.WriteAllText(tmp, root.ToJsonString(WriteOptions));
        File.Move(tmp, path, overwrite: true);
    }
}
