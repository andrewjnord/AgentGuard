using System.Collections.Concurrent;
using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Storage;
using AgentGuard.Service.Platform;

namespace AgentGuard.Service.Services;

public sealed class EnforcementUnavailableException(string message) : Exception(message);
public sealed class EnforcementRefusedException(string message) : Exception(message);

/// <summary>
/// The rules that keep enforcement aimed at AI agents only. Every process and program is checked here before any
/// adapter is called, so the adapters cannot be pointed at system or unrelated software through the API.
/// </summary>
public static class EnforcementGuard
{
    /// <summary>Windows and Linux processes that must never be suspended or ended (names without extension, case-insensitive).</summary>
    public static readonly IReadOnlySet<string> ProtectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Windows core
        "system", "idle", "registry", "memory compression", "secure system", "smss", "csrss", "wininit", "winlogon", "services",
        "lsass", "lsaiso", "svchost", "fontdrvhost", "dwm", "explorer", "sihost", "ctfmon", "taskhostw", "runtimebroker", "userinit",
        "logonui", "spoolsv", "audiodg", "wmiprvse", "trustedinstaller", "tiworker", "searchindexer", "searchhost", "startmenuexperiencehost",
        "shellexperiencehost", "textinputhost", "lockapp", "dllhost", "wudfhost", "dashost", "smartscreen",
        // Security products
        "msmpeng", "mssense", "nissrv", "securityhealthservice", "securityhealthsystray", "mpdefendercoreservice", "sense", "csfalconservice",
        // Linux core
        "init", "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "kthreadd", "dbus-daemon", "sshd", "login", "Xorg", "gnome-shell",
    };

    /// <summary>Programs shared by many applications. A firewall rule on one of these would cut off unrelated software, so it is refused.</summary>
    public static readonly IReadOnlySet<string> SharedRuntimes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "node", "nodejs", "bun", "deno", "python", "python3", "pythonw", "py", "pyw", "java", "javaw", "dotnet", "ruby", "perl", "php",
        "cmd", "powershell", "pwsh", "bash", "sh", "wsl", "wslhost", "conhost", "git", "rundll32", "msedgewebview2", "msedge", "chrome",
        "firefox", "brave", "electron", "uv", "uvx", "npx", "docker",
    };

    private static string Stem(string nameOrPath) =>
        Path.GetFileNameWithoutExtension(nameOrPath.Replace('\\', '/').Split('/').Last());

    /// <summary>Why a process may not be acted on, or null when it may.</summary>
    public static string? ProcessRefusal(AttributedProcess? attributed, int pid, IProcessController controller, ProcessTarget? live)
    {
        if (pid <= 4) return "system process";
        if (pid == Environment.ProcessId) return "AgentGuard itself";
        if (attributed is null) return "not attributed to an AI agent";
        if (attributed.AgentId == "agentguard") return "AgentGuard itself";
        if (live is null) return "process has exited";
        if (live.StartTime != attributed.Process.StartTime && attributed.Process.StartTime != DateTimeOffset.MinValue)
            return "process id was reused by another program";
        var stem = Stem(live.ExePath ?? live.Name);
        if (ProtectedNames.Contains(stem) || ProtectedNames.Contains(Stem(live.Name))) return $"{live.Name} is a protected system process";
        if (stem.StartsWith("agentguard", StringComparison.OrdinalIgnoreCase)) return "AgentGuard component";
        if (controller.IsProtectedByOs(pid)) return "marked critical by the operating system or running as a service";
        return null;
    }

    /// <summary>Program paths that may carry a per-agent firewall rule, plus the reasons the others were refused.</summary>
    public static (List<string> Allowed, List<string> Refused) FirewallPrograms(IEnumerable<string?> candidatePaths)
    {
        var allowed = new List<string>();
        var refused = new List<string>();
        var windir = Environment.GetEnvironmentVariable("SystemRoot") ?? Environment.GetEnvironmentVariable("windir");
        foreach (var raw in candidatePaths.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p!).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string full;
            try { full = Path.GetFullPath(raw); } catch { refused.Add($"{raw}: invalid path"); continue; }
            var stem = Stem(full);
            if (!Path.IsPathRooted(raw)) refused.Add($"{raw}: not an absolute path");
            else if (SharedRuntimes.Contains(stem)) refused.Add($"{Path.GetFileName(full)} is a shared runtime used by other applications");
            else if (ProtectedNames.Contains(stem) || stem.StartsWith("agentguard", StringComparison.OrdinalIgnoreCase)) refused.Add($"{Path.GetFileName(full)} is protected");
            else if (windir is not null && full.StartsWith(windir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) refused.Add($"{Path.GetFileName(full)} is part of Windows");
            else if (!OperatingSystem.IsWindows() && (full.StartsWith("/usr/", StringComparison.Ordinal) || full.StartsWith("/bin/", StringComparison.Ordinal) || full.StartsWith("/sbin/", StringComparison.Ordinal)))
                refused.Add($"{full} is a system program");
            else if (!File.Exists(full)) refused.Add($"{full} does not exist");
            else if (!allowed.Contains(full, StringComparer.OrdinalIgnoreCase)) allowed.Add(full);
        }
        return (allowed, refused);
    }
}

/// <summary>Applies process control and network blocking to AI agents through the platform adapters, enforcing <see cref="EnforcementGuard"/>.</summary>
public sealed class EnforcementService
{
    private const string SuspendedKey = "enforcement.suspended";

    private readonly IEnforcementAdapters _adapters;
    private readonly AgentRegistry _agents;
    private readonly EventStore _store;
    private readonly ILogger<EnforcementService> _log;
    private readonly object _gate = new();
    // Processes AgentGuard suspended, so "resume" only undoes our own suspensions.
    private readonly ConcurrentDictionary<int, (ProcessTarget Target, string AgentId)> _suspended = new();

    public EnforcementService(IEnforcementAdapters adapters, AgentRegistry agents, EventStore store, ILogger<EnforcementService> log)
    {
        _adapters = adapters;
        _agents = agents;
        _store = store;
        _log = log;
        LoadSuspended();
    }

    public int SuspendedCount => _suspended.Count;
    public bool ProcessControl => _adapters.ProcessControl;
    public bool Firewall => _adapters.Firewall;

    private IProcessController Controller =>
        _adapters.Processes ?? throw new EnforcementUnavailableException("Process control is not available on this machine.");

    public sealed record Outcome(int Affected, IReadOnlyList<string> Refused);

    public Outcome SuspendAgent(string agentId) => Act(_agents.Pids(agentId), ActSuspend);
    public Outcome TerminateAgent(string agentId) => Act(OrderForTermination(_agents.Pids(agentId)), ActTerminate);

    public Outcome ResumeAgent(string agentId)
    {
        var c = Controller;
        var pids = _suspended.Where(kv => kv.Value.AgentId == agentId).Select(kv => kv.Key).ToList();
        return ResumePids(c, pids);
    }

    /// <summary>Kill switch: suspend every process attributed to any agent.</summary>
    public Outcome SuspendAll() => Act(_agents.Attributor.AllPids(), ActSuspend);

    public Outcome ResumeAll() => ResumePids(Controller, _suspended.Keys.ToList());

    public Outcome TerminateAll() => Act(OrderForTermination(_agents.Attributor.AllPids()), ActTerminate);

    /// <summary>Suspends one process (automatic response to a blocked detect-only event).</summary>
    public bool TrySuspendProcess(int pid)
    {
        if (!_adapters.ProcessControl) return false;
        return Act(new[] { pid }, ActSuspend).Affected == 1;
    }

    private Outcome ResumePids(IProcessController c, List<int> pids)
    {
        var n = 0;
        lock (_gate)
        {
            foreach (var pid in pids)
            {
                if (!_suspended.TryRemove(pid, out var entry)) continue;
                var live = c.Live(pid);
                if (live is null || live.StartTime != entry.Target.StartTime) continue; // gone or reused: nothing of ours to resume
                if (c.Resume(entry.Target)) n++;
            }
            SaveSuspended();
        }
        return new Outcome(n, Array.Empty<string>());
    }

    private Outcome Act(IEnumerable<int> pids, Func<IProcessController, ProcessTarget, string, bool> action)
    {
        var c = Controller;
        var n = 0;
        var refused = new List<string>();
        lock (_gate)
        {
            foreach (var pid in pids.Distinct())
            {
                var attributed = _agents.Attributor.Get(pid);
                var live = c.Live(pid);
                var why = EnforcementGuard.ProcessRefusal(attributed, pid, c, live);
                if (why is not null)
                {
                    refused.Add($"{pid}: {why}");
                    continue;
                }
                try
                {
                    if (action(c, live!, attributed!.AgentId)) n++;
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Enforcement action failed for pid {Pid}.", pid);
                    refused.Add($"{pid}: {ex.Message}");
                }
            }
            SaveSuspended();
        }
        if (refused.Count > 0) _log.LogInformation("Enforcement skipped {Count} process(es): {Reasons}", refused.Count, string.Join("; ", refused.Take(10)));
        return new Outcome(n, refused);
    }

    private bool ActSuspend(IProcessController c, ProcessTarget p, string agentId)
    {
        if (_suspended.ContainsKey(p.Pid)) return false;
        if (!c.Suspend(p)) return false;
        _suspended[p.Pid] = (p, agentId);
        return true;
    }

    private bool ActTerminate(IProcessController c, ProcessTarget p, string agentId)
    {
        _suspended.TryRemove(p.Pid, out _);
        return c.Terminate(p);
    }

    /// <summary>Children before parents, so a parent cannot respawn a child we just ended.</summary>
    private IEnumerable<int> OrderForTermination(IEnumerable<int> pids)
    {
        var current = _agents.Attributor.Current;
        int Depth(int pid)
        {
            var d = 0;
            var seen = new HashSet<int>();
            while (current.TryGetValue(pid, out var a) && a.Process.ParentPid is { } pp && seen.Add(pid) && d < 64) { pid = pp; d++; }
            return d;
        }
        return pids.Distinct().OrderByDescending(Depth).ToList();
    }

    // ------------------------------------------------------------------ network

    /// <summary>Blocks or unblocks outbound network access for the agent's own executables.</summary>
    public AgentRecord SetNetworkBlocked(string agentId, bool blocked)
    {
        var record = _agents.Get(agentId) ?? throw new KeyNotFoundException($"Agent {agentId} not found.");
        var net = _adapters.Network ?? throw new EnforcementUnavailableException("Per-agent network blocking is not available on this machine.");
        if (agentId == "agentguard") throw new EnforcementRefusedException("AgentGuard cannot block itself.");

        if (blocked)
        {
            var candidates = _agents.Attributor.Current.Values
                .Where(a => a.AgentId == agentId && a.IsRoot)
                .Select(a => a.Process.ExePath)
                .Append(record.ExePath);
            var (allowed, refused) = EnforcementGuard.FirewallPrograms(candidates);
            if (allowed.Count == 0)
            {
                var why = refused.Count > 0 ? string.Join("; ", refused) : "no executable path is known for this agent yet (start it once so AgentGuard can see it)";
                throw new EnforcementRefusedException($"Network blocking was not applied: {why}. Use policy net.connect rules (enforced through hooks and the MCP proxy) instead.");
            }
            net.Block(agentId, allowed);
            _log.LogInformation("Blocked network for {Agent}: {Programs}", agentId, string.Join(", ", allowed));
        }
        else
        {
            net.Unblock(agentId);
        }
        return _agents.SetNetworkBlocked(agentId, blocked)!;
    }

    // ------------------------------------------------------------------ persistence

    private sealed record SavedSuspension(int Pid, DateTimeOffset StartTime, string Name, string? ExePath, string AgentId);

    private void SaveSuspended()
    {
        var list = _suspended.Values.Select(v => new SavedSuspension(v.Target.Pid, v.Target.StartTime, v.Target.Name, v.Target.ExePath, v.AgentId)).ToList();
        _store.SetSetting(SuspendedKey, Json.Serialize(list));
    }

    /// <summary>Processes suspended by a previous run are reloaded so they can be resumed (and are resumed on start if the kill switch is off).</summary>
    private void LoadSuspended()
    {
        var json = _store.GetSetting(SuspendedKey);
        if (string.IsNullOrEmpty(json)) return;
        foreach (var s in Json.Deserialize<List<SavedSuspension>>(json) ?? new())
            _suspended[s.Pid] = (new ProcessTarget(s.Pid, s.StartTime, s.Name, s.ExePath), s.AgentId);
    }

    /// <summary>Called at startup: resume anything left suspended unless the kill switch is still engaged.</summary>
    public int RecoverAfterRestart(bool killSwitchEngaged)
    {
        if (killSwitchEngaged || _suspended.IsEmpty || _adapters.Processes is null) return 0;
        var n = ResumeAll().Affected;
        if (n > 0) _log.LogWarning("Resumed {Count} process(es) left suspended by a previous AgentGuard run.", n);
        return n;
    }
}
