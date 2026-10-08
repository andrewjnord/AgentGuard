using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using AgentGuard.Core.Policy;

namespace AgentGuard.Core.Discovery;

public sealed class SignatureFile
{
    public List<AgentSignature> Agents { get; set; } = new();
    public List<McpClientDefinition> McpClients { get; set; } = new();
    /// <summary>Process names (globs) attributed to agents but never reported as separate process events (shell hosts, our own helpers).</summary>
    public List<string> QuietProcesses { get; set; } = new();
    /// <summary>Process names (globs) never attributed to any agent (AgentGuard itself).</summary>
    public List<string> IgnoreProcesses { get; set; } = new();
    /// <summary>Process names (globs) treated as shells: their launches are reported as shell.exec.</summary>
    public List<string> Shells { get; set; } = new();

    public static SignatureFile Load(string path) => Parse(File.ReadAllText(path));

    public static SignatureFile Parse(string yaml)
    {
        var d = new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance).Build();
        return d.Deserialize<SignatureFile>(yaml) ?? new SignatureFile();
    }
}

public sealed class AgentSignature
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Kind { get; set; } = AgentKinds.Unknown;
    public string? Publisher { get; set; }
    public List<SignatureMatch> Match { get; set; } = new();

    public bool Matches(ProcessInfo p)
    {
        foreach (var m in Match)
        {
            if (!Glob.IsMatch(m.Process, p.Name)) continue;
            var cmdline = (p.CommandLine ?? "").Replace('\\', '/');
            if (m.Cmdline is { Count: > 0 } && !m.Cmdline.Any(c => cmdline.Contains(c.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase))) continue;
            var exe = Glob.NormalizePath(p.ExePath ?? "");
            if (m.Path is { Count: > 0 } && !m.Path.Any(g => Glob.IsMatch(g, exe, pathMode: true))) continue;
            if (m.PathNot is { Count: > 0 } && m.PathNot.Any(g => Glob.IsMatch(g, exe, pathMode: true))) continue;
            return true;
        }
        return false;
    }
}

public sealed class SignatureMatch
{
    public string Process { get; set; } = "";
    public List<string>? Cmdline { get; set; }
    public List<string>? Path { get; set; }
    public List<string>? PathNot { get; set; }
}

public sealed class McpClientDefinition
{
    public string Client { get; set; } = "";
    public List<string> Paths { get; set; } = new();
    public string ServersKey { get; set; } = "mcpServers";
    public string Scope { get; set; } = "user";
    /// <summary>Claude Code keeps per-project servers under "projects.&lt;path&gt;.mcpServers" and in "&lt;project&gt;/.mcp.json".</summary>
    public bool ClaudeCodeProjects { get; set; }
}

public sealed record ProcessInfo(
    int Pid,
    int? ParentPid,
    string Name,
    string? ExePath,
    string? CommandLine,
    DateTimeOffset StartTime,
    string? UserProfile = null);
