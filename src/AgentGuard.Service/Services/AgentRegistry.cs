using System.Collections.Concurrent;
using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Storage;

namespace AgentGuard.Service.Services;

/// <summary>Known agents, their trust setting, and the processes currently attributed to them.</summary>
public sealed class AgentRegistry
{
    private readonly EventStore _store;
    private readonly ConcurrentDictionary<string, AgentRecord> _agents = new();
    private readonly ConcurrentDictionary<string, byte> _hooksSeen = new();

    public AgentAttributor Attributor { get; }

    public AgentRegistry(EventStore store, AgentAttributor attributor)
    {
        _store = store;
        Attributor = attributor;
        foreach (var a in store.ListAgents()) _agents[a.Id] = a;
    }

    public IReadOnlyList<AgentRecord> All() => _agents.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();

    public AgentRecord? Get(string id) => _agents.TryGetValue(id, out var a) ? a : null;

    public string TrustOf(string id) => Get(id)?.Trust ?? "unknown";

    public IReadOnlyList<int> Pids(string id) => Attributor.PidsFor(id);

    public bool IsRunning(string id) => Pids(id).Count > 0;

    /// <summary>Registers or refreshes an agent. Returns true when the agent was never seen before.</summary>
    public bool Ensure(string id, string name, string kind, string? exePath = null, string? publisher = null)
    {
        var now = DateTimeOffset.UtcNow;
        var isNew = false;
        var record = _agents.AddOrUpdate(id,
            _ =>
            {
                isNew = true;
                return new AgentRecord { Id = id, Name = name, Kind = kind, ExePath = exePath, Publisher = publisher, FirstSeen = now, LastSeen = now };
            },
            (_, existing) =>
            {
                existing.LastSeen = now;
                existing.ExePath ??= exePath;
                existing.Publisher ??= publisher;
                if (existing.Kind == AgentKinds.Unknown) existing.Kind = kind;
                return existing;
            });
        _store.UpsertAgent(record);
        return isNew;
    }

    public AgentRecord? SetTrust(string id, string trust)
    {
        if (!_agents.TryGetValue(id, out var a)) return null;
        a.Trust = trust;
        _store.UpsertAgent(a);
        return a;
    }

    public void MarkHookSeen(string agentId) => _hooksSeen[agentId] = 1;
    public bool HookSeen(string agentId) => _hooksSeen.ContainsKey(agentId);
}
