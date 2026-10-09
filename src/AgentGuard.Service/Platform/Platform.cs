using AgentGuard.Core.Discovery;

namespace AgentGuard.Service.Platform;

/// <summary>Lists running processes with parent ids and command lines.</summary>
public interface IProcessSource
{
    IReadOnlyList<ProcessInfo> Snapshot();
}

/// <summary>A specific process instance. The start time guards against acting on a reused process id.</summary>
public sealed record ProcessTarget(int Pid, DateTimeOffset StartTime, string Name, string? ExePath);

/// <summary>Suspends, resumes and ends individual processes. Implementations do OS work only; every safety check lives in <see cref="EnforcementGuard"/>.</summary>
public interface IProcessController
{
    /// <summary>True when the OS marks the process as critical (ending it would crash the machine) or it runs as a service in session 0.</summary>
    bool IsProtectedByOs(int pid);
    /// <summary>Returns the live process for <paramref name="pid"/> if it is still the same instance, else null.</summary>
    ProcessTarget? Live(int pid);
    bool Suspend(ProcessTarget p);
    bool Resume(ProcessTarget p);
    bool Terminate(ProcessTarget p);
}

/// <summary>Per-program outbound network blocking, one rule group per agent.</summary>
public interface INetworkBlocker
{
    void Block(string agentId, IReadOnlyCollection<string> programPaths);
    void Unblock(string agentId);
    /// <summary>Agents that currently have blocking rules installed.</summary>
    IReadOnlyCollection<string> BlockedAgents();
}

/// <summary>One observed OS activity record.</summary>
public sealed record TelemetryEvent(DateTimeOffset Ts, int Pid, string Kind, string Target, IReadOnlyDictionary<string, object?>? Details = null, ProcessInfo? Process = null);

public static class TelemetryKinds
{
    public const string ProcessStart = "process.start";
    public const string ProcessStop = "process.stop";
    public const string FileWrite = "file.write";
    public const string FileDelete = "file.delete";
    public const string NetConnect = "net.connect";
}

/// <summary>Real-time OS activity. <paramref name="isInteresting"/> lets the source drop events from processes that are not agents as early as possible.</summary>
public interface ITelemetrySource : IDisposable
{
    void Start(Action<TelemetryEvent> onEvent, Func<int, bool> isInteresting, Action<Exception> onError);
}

/// <summary>Code-signing lookup for agent executables.</summary>
public interface IFileTrust
{
    (string? Publisher, bool? SignerValid) Inspect(string exePath);
}

/// <summary>
/// The endpoint enforcement adapters available on this machine. A null member means the capability is unavailable,
/// and the API reports it as such rather than pretending to act.
/// </summary>
public interface IEnforcementAdapters
{
    IProcessController? Processes { get; }
    INetworkBlocker? Network { get; }
    Func<ITelemetrySource>? TelemetryFactory { get; }
    IFileTrust? FileTrust { get; }

    bool Telemetry => TelemetryFactory is not null;
    bool ProcessControl => Processes is not null;
    bool Firewall => Network is not null;
}

/// <summary>No adapters (non-Windows, or disabled by configuration).</summary>
public sealed class NoEnforcementAdapters : IEnforcementAdapters
{
    public IProcessController? Processes => null;
    public INetworkBlocker? Network => null;
    public Func<ITelemetrySource>? TelemetryFactory => null;
    public IFileTrust? FileTrust => null;
}

public static class PlatformFactory
{
    public static IProcessSource ProcessSource() =>
        OperatingSystem.IsWindows() ? new Windows.WindowsProcessSource() :
        OperatingSystem.IsLinux() ? new ProcFsProcessSource() : new DotnetProcessSource();

    public static IEnforcementAdapters Adapters(AgentGuardOptions options) =>
        OperatingSystem.IsWindows() && !options.DisableEnforcement
            ? new Windows.WindowsEnforcementAdapters(options)
            : new NoEnforcementAdapters();
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
