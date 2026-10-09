namespace AgentGuard.Core.Integration;

/// <summary>
/// Settings the service publishes for its local clients (MCP proxy, hook, CLI) in a file every user can read. It holds
/// no secrets: just where to reach the service and what to do if it cannot be reached.
/// </summary>
public sealed class ClientConfig
{
    public int Port { get; set; } = AgentGuardClient.DefaultPort;
    /// <summary>"closed" (block when the service is unreachable) or "open" (allow).</summary>
    public string FailMode { get; set; } = "closed";
    public string Version { get; set; } = "";

    public bool FailOpen => FailMode == "open";
    public string BaseUrl => $"http://127.0.0.1:{Port}/";

    public static string DefaultPath()
    {
        if (Environment.GetEnvironmentVariable("AGENTGUARD_CLIENT_CONFIG") is { Length: > 0 } p) return p;
        var root = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AgentGuard")
            : Path.Combine(Environment.GetEnvironmentVariable("AGENTGUARD_DATA_DIR") ?? "/var/lib/agentguard");
        return Path.Combine(root, "public", "client.json");
    }

    /// <summary>Reads the published config, falling back to defaults (fail closed) when it is missing or unreadable.</summary>
    public static ClientConfig Load(string? path = null)
    {
        try
        {
            var file = path ?? DefaultPath();
            if (File.Exists(file)) return Json.Deserialize<ClientConfig>(File.ReadAllText(file)) ?? new ClientConfig();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException) { }
        return new ClientConfig();
    }

    /// <summary>Base URL for clients: AGENTGUARD_URL wins, then the published port.</summary>
    public string ResolveBaseUrl() =>
        Environment.GetEnvironmentVariable("AGENTGUARD_URL") is { Length: > 0 } url ? url.TrimEnd('/') + "/" : BaseUrl;
}
