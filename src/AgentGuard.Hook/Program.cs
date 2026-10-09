using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using AgentGuard.Core;
using AgentGuard.Core.Integration;

namespace AgentGuard.Hook;

/// <summary>
/// agentguard-hook                      PreToolUse hook (Claude Code runs it with the payload on stdin)
/// agentguard-hook install [--user|--managed] [--settings PATH]
/// agentguard-hook uninstall [--user|--managed] [--settings PATH]
/// agentguard-hook status
/// </summary>
public static class HookProgram
{
    public static async Task<int> Main(string[] args)
    {
        var command = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "run";
        try
        {
            return command switch
            {
                "run" => await RunHookAsync(args),
                "install" => Install(args, install: true),
                "uninstall" => Install(args, install: false),
                "status" => Status(),
                _ => Usage(),
            };
        }
        catch (Exception ex) when (command != "run")
        {
            Console.Error.WriteLine($"agentguard-hook {command}: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunHookAsync(string[] args)
    {
        var config = ClientConfig.Load();
        var failOpen = args.Contains("--fail-open") || config.FailOpen;
        string input;
        try { input = await ReadStdinAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex)
        {
            Console.Error.WriteLine((failOpen ? "AgentGuard: " : "Blocked by AgentGuard: ") + "no hook input (" + ex.Message + ").");
            return failOpen ? 0 : 2;
        }

        // Fail fast when the service is down; once connected, wait as long as an approval takes.
        var handler = new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(3), UseProxy = false };
        using var client = new AgentGuardClient(config.ResolveBaseUrl(), timeout: Timeout.InfiniteTimeSpan, handler: handler);
        var runner = new HookRunner(client.DecideAsync, failOpen)
        {
            UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Pid = ParentProcess.Id(),
        };
        try
        {
            return await runner.RunAsync(input, Console.Out, Console.Error);
        }
        catch (Exception ex)
        {
            // Never crash open: an unexpected error blocks unless fail-open is configured.
            Console.Error.WriteLine((failOpen ? "AgentGuard error (allowed, fail-open): " : "Blocked by AgentGuard (internal error): ") + ex.Message);
            return failOpen ? 0 : 2;
        }
    }

    private static async Task<string> ReadStdinAsync(TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        await using var stdin = Console.OpenStandardInput();
        using var ms = new MemoryStream();
        var buffer = new byte[64 * 1024];
        int n;
        while ((n = await stdin.ReadAsync(buffer, cts.Token)) > 0)
        {
            ms.Write(buffer, 0, n);
            if (ms.Length > HookRunner.MaxInputBytes) throw new InvalidDataException("hook input is larger than 4 MB");
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static int Install(string[] args, bool install)
    {
        string path;
        var custom = Array.IndexOf(args, "--settings");
        if (custom >= 0 && custom + 1 < args.Length) path = args[custom + 1];
        else if (args.Contains("--user")) path = ClaudeSettings.UserSettingsPath();
        else path = ClaudeSettings.ManagedDropInPath(); // default: machine-wide (needs an elevated prompt)

        var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "agentguard-hook.exe" : "agentguard-hook");
        if (install)
        {
            ClaudeSettings.Install(path, exe);
            Console.WriteLine($"Registered the AgentGuard PreToolUse hook in {path}");
        }
        else
        {
            Console.WriteLine(ClaudeSettings.Uninstall(path) ? $"Removed the AgentGuard hook from {path}" : $"The AgentGuard hook was not registered in {path}");
        }
        return 0;
    }

    private static int Status()
    {
        var managed = ClaudeSettings.IsInstalled(ClaudeSettings.ManagedDropInPath());
        var user = ClaudeSettings.IsInstalled(ClaudeSettings.UserSettingsPath());
        var config = ClientConfig.Load();
        Console.WriteLine($"Managed hook ({ClaudeSettings.ManagedDropInPath()}): {(managed ? "registered" : "not registered")}");
        Console.WriteLine($"User hook ({ClaudeSettings.UserSettingsPath()}): {(user ? "registered" : "not registered")}");
        Console.WriteLine($"Service: {config.ResolveBaseUrl()} (fail mode: {config.FailMode})");
        return managed || user ? 0 : 1;
    }

    private static int Usage()
    {
        Console.Error.WriteLine("""
            Usage:
              agentguard-hook                         Claude Code PreToolUse hook (reads the payload on stdin)
              agentguard-hook install   [--managed | --user | --settings PATH]
              agentguard-hook uninstall [--managed | --user | --settings PATH]
              agentguard-hook status
            """);
        return 1;
    }
}

/// <summary>The process that launched the hook (Claude Code), so events carry the agent's process id.</summary>
internal static class ParentProcess
{
    public static int? Id()
    {
        try
        {
            if (OperatingSystem.IsWindows()) return WindowsParent(Environment.ProcessId);
            if (OperatingSystem.IsLinux())
            {
                var stat = File.ReadAllText("/proc/self/stat");
                var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
                return int.Parse(fields[1]);
            }
        }
        catch { }
        return null;
    }

    // Toolhelp32 snapshot: the documented way to read a process's parent id.
    private static int? WindowsParent(int pid)
    {
        var snap = CreateToolhelp32Snapshot(0x2 /* TH32CS_SNAPPROCESS */, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return null;
        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref entry)) return null;
            do
            {
                if (entry.th32ProcessID == pid) return (int)entry.th32ParentProcessID;
            } while (Process32NextW(snap, ref entry));
            return null;
        }
        finally { CloseHandle(snap); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W entry);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
}
