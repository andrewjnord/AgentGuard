using AgentGuard.Core.Policy;

namespace AgentGuard.Core.Discovery;

public sealed record AttributedProcess(
    ProcessInfo Process,
    string AgentId,
    string AgentName,
    string Kind,
    string? Publisher,
    // True when this process itself matched a signature (the agent main process); false when inherited from a parent.
    bool IsRoot,
    bool IsShell,
    bool IsQuiet);

public sealed record AttributionDiff(IReadOnlyList<AttributedProcess> Started, IReadOnlyList<AttributedProcess> Exited);

/// <summary>
/// Assigns running processes to AI agents. A process belongs to an agent if it matches the agent's signature,
/// or if its parent belongs to an agent (so shells, interpreters and MCP servers started by an agent are attributed to it).
/// </summary>
public sealed class AgentAttributor
{
    public const string ProxyProcessName = "agentguard-mcp-proxy";

    private readonly SignatureFile _signatures;
    private readonly object _gate = new();
    private Dictionary<int, AttributedProcess> _current = new();

    public AgentAttributor(SignatureFile signatures) => _signatures = signatures;

    public IReadOnlyDictionary<int, AttributedProcess> Current
    {
        get { lock (_gate) return new Dictionary<int, AttributedProcess>(_current); }
    }

    public AttributedProcess? Get(int pid)
    {
        lock (_gate) return _current.TryGetValue(pid, out var a) ? a : null;
    }

    public IReadOnlyList<int> PidsFor(string agentId)
    {
        lock (_gate) return _current.Values.Where(a => a.AgentId == agentId).Select(a => a.Process.Pid).ToList();
    }

    public IReadOnlyList<int> AllPids()
    {
        lock (_gate) return _current.Keys.ToList();
    }

    /// <summary>Replaces the known process set with a fresh snapshot and returns what started and exited.</summary>
    public AttributionDiff Update(IReadOnlyList<ProcessInfo> snapshot)
    {
        var byPid = new Dictionary<int, ProcessInfo>();
        foreach (var p in snapshot) byPid[p.Pid] = p;

        var resolved = new Dictionary<int, AttributedProcess?>();
        foreach (var p in snapshot) Resolve(p, byPid, resolved, 0);

        var next = resolved.Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value!);
        lock (_gate)
        {
            var started = next.Values.Where(a => !_current.TryGetValue(a.Process.Pid, out var old) || old.Process.StartTime != a.Process.StartTime).ToList();
            var exited = _current.Values.Where(a => !next.TryGetValue(a.Process.Pid, out var now) || now.Process.StartTime != a.Process.StartTime).ToList();
            _current = next;
            return new AttributionDiff(started, exited);
        }
    }

    /// <summary>Attributes a single newly started process using the current state (used by real-time telemetry).</summary>
    public AttributedProcess? Add(ProcessInfo p)
    {
        lock (_gate)
        {
            var map = _current.ToDictionary(kv => kv.Key, kv => kv.Value.Process);
            map[p.Pid] = p;
            var resolved = _current.ToDictionary(kv => kv.Key, kv => (AttributedProcess?)kv.Value);
            resolved.Remove(p.Pid);
            var a = Resolve(p, map, resolved, 0);
            if (a is not null) _current[p.Pid] = a;
            return a;
        }
    }

    public AttributedProcess? Remove(int pid)
    {
        lock (_gate)
        {
            if (!_current.Remove(pid, out var a)) return null;
            return a;
        }
    }

    private AttributedProcess? Resolve(ProcessInfo p, Dictionary<int, ProcessInfo> byPid, Dictionary<int, AttributedProcess?> memo, int depth)
    {
        if (memo.TryGetValue(p.Pid, out var cached)) return cached;
        memo[p.Pid] = null; // cycle guard
        if (depth > 64 || IsAny(_signatures.IgnoreProcesses, p.Name)) return null;

        AttributedProcess? result = null;
        var proxy = TryProxy(p);
        if (proxy is not null)
        {
            result = proxy;
        }
        else
        {
            var sig = _signatures.Agents.FirstOrDefault(s => s.Matches(p));
            if (sig is not null)
            {
                result = new AttributedProcess(p, sig.Id, sig.Name, sig.Kind, sig.Publisher, true, IsShell(p), IsQuiet(p));
            }
            else if (p.ParentPid is { } ppid && ppid != p.Pid && byPid.TryGetValue(ppid, out var parent) && parent.StartTime <= p.StartTime)
            {
                var pa = Resolve(parent, byPid, memo, depth + 1);
                if (pa is not null)
                    result = new AttributedProcess(p, pa.AgentId, pa.AgentName, pa.Kind, pa.Publisher, false, IsShell(p), IsQuiet(p));
            }
        }
        memo[p.Pid] = result;
        return result;
    }

    /// <summary>Processes started through the AgentGuard MCP proxy are attributed to the MCP server, not the client that launched them.</summary>
    private static AttributedProcess? TryProxy(ProcessInfo p)
    {
        var name = Path.GetFileNameWithoutExtension(p.Name);
        if (!name.Equals(ProxyProcessName, StringComparison.OrdinalIgnoreCase) || p.CommandLine is null) return null;
        var server = McpProxyArgs.ServerNameFromCommandLine(p.CommandLine);
        if (server is null) return null;
        return new AttributedProcess(p, "mcp:" + server, "MCP: " + server, AgentKinds.McpServer, null, true, false, true);
    }

    private bool IsShell(ProcessInfo p) => IsAny(_signatures.Shells, p.Name);
    private bool IsQuiet(ProcessInfo p) => IsAny(_signatures.QuietProcesses, p.Name);
    private static bool IsAny(List<string> globs, string name) => globs.Any(g => Glob.IsMatch(g, name));
}
