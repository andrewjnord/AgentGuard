using AgentGuard.Core.Discovery;

namespace AgentGuard.Service.Platform;

/// <summary>Lists running processes with parent ids and command lines.</summary>
public interface IProcessSource
{
    IReadOnlyList<ProcessInfo> Snapshot();
}

/// <summary>
/// Extension point for endpoint enforcement: OS telemetry (file, network, process activity), process suspend/terminate,
/// per-program network blocking and Authenticode inspection. v1 ships these as unavailable; see docs/enforcement-adapters.md.
/// </summary>
public interface IEnforcementAdapters
{
    /// <summary>Real-time OS telemetry is delivered.</summary>
    bool Telemetry { get; }
    /// <summary>Agent processes can be suspended and terminated.</summary>
    bool ProcessControl { get; }
    /// <summary>Per-agent network blocking is available.</summary>
    bool Firewall { get; }
}

/// <summary>v1 default: no endpoint enforcement adapters are installed.</summary>
public sealed class NoEnforcementAdapters : IEnforcementAdapters
{
    public bool Telemetry => false;
    public bool ProcessControl => false;
    public bool Firewall => false;
}

public static class PlatformFactory
{
    public static IProcessSource ProcessSource() =>
        OperatingSystem.IsWindows() ? new Windows.WindowsProcessSource() :
        OperatingSystem.IsLinux() ? new ProcFsProcessSource() : new DotnetProcessSource();
}

/// <summary>Linux /proc reader, so the service can run (and be developed and tested) off Windows.</summary>
public sealed class ProcFsProcessSource : IProcessSource
{
    private static readonly DateTimeOffset BootTime = ReadBootTime();
    private static readonly long ClockTicks = 100;

    public IReadOnlyList<ProcessInfo> Snapshot()
    {
        var list = new List<ProcessInfo>();
        foreach (var dir in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(dir), out var pid)) continue;
            try
            {
                var stat = File.ReadAllText(Path.Combine(dir, "stat"));
                var close = stat.LastIndexOf(')');
                var name = stat[(stat.IndexOf('(') + 1)..close];
                var fields = stat[(close + 2)..].Split(' ');
                var ppid = int.Parse(fields[1]);
                var startTicks = long.Parse(fields[19]);
                var cmdline = File.ReadAllText(Path.Combine(dir, "cmdline")).Replace('\0', ' ').Trim();
                string? exe = null;
                try { exe = new FileInfo(Path.Combine(dir, "exe")).LinkTarget; } catch { }
                if (exe is not null) name = Path.GetFileName(exe);
                list.Add(new ProcessInfo(pid, ppid, name, exe, cmdline.Length > 0 ? cmdline : name, BootTime.AddSeconds(startTicks / (double)ClockTicks)));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or IndexOutOfRangeException) { }
        }
        return list;
    }

    private static DateTimeOffset ReadBootTime()
    {
        try
        {
            var line = File.ReadLines("/proc/stat").FirstOrDefault(l => l.StartsWith("btime ", StringComparison.Ordinal));
            if (line is not null) return DateTimeOffset.FromUnixTimeSeconds(long.Parse(line[6..].Trim()));
        }
        catch { }
        return DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
    }
}

/// <summary>Fallback process source with no parent information.</summary>
public sealed class DotnetProcessSource : IProcessSource
{
    public IReadOnlyList<ProcessInfo> Snapshot()
    {
        var list = new List<ProcessInfo>();
        foreach (var p in System.Diagnostics.Process.GetProcesses())
        {
            try { list.Add(new ProcessInfo(p.Id, null, p.ProcessName, null, p.ProcessName, p.StartTime.ToUniversalTime())); }
            catch { }
            finally { p.Dispose(); }
        }
        return list;
    }
}
