namespace AgentGuard.Service;

public sealed class AgentGuardOptions
{
    public const string Section = "AgentGuard";

    /// <summary>Where the database, policy, token and allowlists live.</summary>
    public string DataDir { get; set; } = "";
    public int Port { get; set; } = 47823;
    /// <summary>Relaxes the tray handshake and allows a fixed token. Never enable on a production install.</summary>
    public bool DevMode { get; set; }
    /// <summary>Generates realistic simulated agent activity (for demos and UI work).</summary>
    public bool Demo { get; set; }
    /// <summary>Fixed admin token (dev/test only). When empty a random token is generated at each start.</summary>
    public string? Token { get; set; }
    /// <summary>Directory holding the installed binaries (proxy, hooks CLI, tray).</summary>
    public string InstallDir { get; set; } = AppContext.BaseDirectory;
    /// <summary>Disables the background workers (discovery, telemetry). Used by tests.</summary>
    public bool DisableWorkers { get; set; }
    /// <summary>Overrides the user profile directories scanned for MCP configs (tests).</summary>
    public List<string>? UserProfiles { get; set; }

    public string DatabasePath => Path.Combine(DataDir, "agentguard.db");
    public string PolicyPath => Path.Combine(DataDir, "policy.yaml");
    public string TokenPath => Path.Combine(DataDir, "admin.token");
    public string SignaturesPath => File.Exists(Path.Combine(DataDir, "signatures", "agents.yaml"))
        ? Path.Combine(DataDir, "signatures", "agents.yaml")
        : Path.Combine(AppContext.BaseDirectory, "defaults", "signatures", "agents.yaml");

    public string ExeName(string baseName) => OperatingSystem.IsWindows() ? baseName + ".exe" : baseName;
    public string ProxyPath => Path.Combine(InstallDir, ExeName("agentguard-mcp-proxy"));
    public string HookPath => Path.Combine(InstallDir, ExeName("agentguard-hook"));
    public string TrayPath => Path.Combine(InstallDir, ExeName("AgentGuard.Tray"));

    public void ApplyDefaults()
    {
        if (string.IsNullOrWhiteSpace(DataDir))
        {
            DataDir = OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AgentGuard")
                : Path.Combine(Directory.GetCurrentDirectory(), "data");
        }
        DataDir = Path.GetFullPath(DataDir);
    }
}
