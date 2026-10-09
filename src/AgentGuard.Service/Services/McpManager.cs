using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Storage;

namespace AgentGuard.Service.Services;

/// <summary>Finds MCP servers in client configs and routes them through (or away from) the AgentGuard proxy.</summary>
public sealed class McpManager
{
    private static readonly Dictionary<string, string> ClientAgent = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Claude Desktop"] = "claude-desktop",
        ["Claude Code"] = "claude-code",
        ["Cursor"] = "cursor",
        ["VS Code"] = "vscode",
        ["Windsurf"] = "windsurf",
    };

    private readonly AgentGuardOptions _options;
    private readonly EventStore _store;
    private readonly SignatureFile _signatures;
    private readonly EventBus _bus;
    private readonly ILogger<McpManager> _log;
    private readonly object _gate = new();

    public McpManager(AgentGuardOptions options, EventStore store, SignatureFile signatures, EventBus bus, ILogger<McpManager> log)
    {
        _options = options;
        _store = store;
        _signatures = signatures;
        _bus = bus;
        _log = log;
    }

    public static string? AgentForClient(string client) => ClientAgent.TryGetValue(client, out var id) ? id : null;

    public List<McpServerRecord> List() => _store.ListMcpServers();

    public McpServerRecord? Get(string id) => _store.GetMcpServer(id);

    public IEnumerable<string> UserProfiles()
    {
        if (_options.UserProfiles is { Count: > 0 } configured) return configured;
        var result = new List<string>();
        if (OperatingSystem.IsWindows())
        {
            var usersRoot = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users";
            var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Public", "Default", "Default User", "All Users", "WDAGUtilityAccount" };
            if (Directory.Exists(usersRoot))
                result.AddRange(Directory.GetDirectories(usersRoot).Where(d => !skip.Contains(Path.GetFileName(d))));
        }
        else
        {
            if (Directory.Exists("/home")) result.AddRange(Directory.GetDirectories("/home"));
            if (Directory.Exists("/root")) result.Add("/root");
            var home = Environment.GetEnvironmentVariable("HOME");
            if (!string.IsNullOrEmpty(home)) result.Add(home);
        }
        return result.Distinct();
    }

    public List<McpServerRecord> Rescan()
    {
        lock (_gate)
        {
            var found = McpConfigScanner.Scan(_signatures.McpClients, UserProfiles());
            foreach (var s in found)
            {
                var existing = _store.GetMcpServer(s.Id);
                if (existing is not null)
                {
                    s.UpstreamUrl = existing.UpstreamUrl;
                    s.LastCallAt = existing.LastCallAt;
                }
                _store.UpsertMcpServer(s);
            }
            _store.MarkMcpServersMissing(found.Select(s => s.Id).ToList());
            return _store.ListMcpServers();
        }
    }

    public McpServerRecord SetProxied(string id, bool enabled)
    {
        lock (_gate)
        {
            var s = _store.GetMcpServer(id) ?? throw new KeyNotFoundException($"MCP server {id} not found.");
            if (s.Proxied == enabled) return s;

            if (s.Transport == "stdio")
            {
                if (enabled)
                {
                    if (!File.Exists(_options.ProxyPath))
                        throw new InvalidOperationException($"The MCP proxy is not installed at {_options.ProxyPath}.");
                    McpConfigRewriter.WrapStdio(s.ConfigPath, s.JsonPath, _options.ProxyPath, s.Name);
                }
                else McpConfigRewriter.UnwrapStdio(s.ConfigPath, s.JsonPath);
            }
            else
            {
                if (enabled)
                {
                    var forwarder = $"http://127.0.0.1:{_options.Port}/mcp/{s.Id}";
                    s.UpstreamUrl = McpConfigRewriter.SetUrl(s.ConfigPath, s.JsonPath, forwarder);
                }
                else
                {
                    if (string.IsNullOrEmpty(s.UpstreamUrl)) throw new InvalidOperationException("The original server URL is unknown; edit the client config by hand.");
                    McpConfigRewriter.SetUrl(s.ConfigPath, s.JsonPath, s.UpstreamUrl);
                    s.UpstreamUrl = null;
                }
            }
            s.Proxied = enabled;
            _store.UpsertMcpServer(s);
            _log.LogInformation("MCP server {Name} ({Client}) proxy {State}.", s.Name, s.Client, enabled ? "enabled" : "disabled");
            _bus.Publish("mcp", s);
            return s;
        }
    }

    public void TouchCall(string agentId)
    {
        if (!agentId.StartsWith("mcp:", StringComparison.Ordinal)) return;
        var name = agentId[4..];
        foreach (var s in _store.ListMcpServers().Where(s => s.Name == name && s.Proxied))
        {
            s.LastCallAt = DateTimeOffset.UtcNow;
            _store.UpsertMcpServer(s);
        }
    }
}
