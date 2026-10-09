using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace AgentGuard.McpProxy;

/// <summary>Finds and starts the real MCP server the way a shell would (PATH, and on Windows PATHEXT and .cmd shims such as npx).</summary>
public static class ChildProcess
{
    public static ProcessStartInfo Build(string command, IReadOnlyList<string> args)
    {
        var psi = new ProcessStartInfo
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = false, // the server's log goes straight to the client's log
            CreateNoWindow = true,
            StandardOutputEncoding = new UTF8Encoding(false),
            WorkingDirectory = Environment.CurrentDirectory,
        };
        if (!OperatingSystem.IsWindows())
        {
            psi.FileName = command;
            foreach (var a in args) psi.ArgumentList.Add(a);
            return psi;
        }

        var resolved = ResolveWindows(command) ?? command;
        var ext = Path.GetExtension(resolved).ToLowerInvariant();
        if (ext is ".cmd" or ".bat")
        {
            // Batch files run through cmd.exe; quote and caret-escape so arguments reach the script unchanged.
            psi.FileName = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
            var line = new StringBuilder();
            line.Append(EscapeForCmd(resolved));
            foreach (var a in args) line.Append(' ').Append(EscapeForCmd(a));
            psi.Arguments = $"/d /s /c \"{line}\"";
        }
        else
        {
            psi.FileName = resolved;
            foreach (var a in args) psi.ArgumentList.Add(a);
        }
        return psi;
    }

    /// <summary>Searches PATH with PATHEXT, as cmd.exe does.</summary>
    public static string? ResolveWindows(string command, string? pathVar = null, string? pathExt = null)
    {
        var exts = (pathExt ?? Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD")
            .Split(';', StringSplitOptions.RemoveEmptyEntries);
        IEnumerable<string> Candidates(string basePath) =>
            Path.HasExtension(basePath) ? new[] { basePath }.Concat(exts.Select(e => basePath + e)) : exts.Select(e => basePath + e);

        if (command.Contains('\\') || command.Contains('/') || Path.IsPathRooted(command))
            return Candidates(command).FirstOrDefault(File.Exists);

        foreach (var dir in (pathVar ?? Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            string full;
            try { full = Path.Combine(dir.Trim('"'), command); } catch (ArgumentException) { continue; }
            if (Candidates(full).FirstOrDefault(File.Exists) is { } hit) return hit;
        }
        return null;
    }

    /// <summary>
    /// Escapes one argument for a cmd.exe /s /c line: CommandLineToArgvW quoting, then caret-escaping of cmd metacharacters
    /// (the same approach as cross-spawn).
    /// </summary>
    public static string EscapeForCmd(string arg)
    {
        var sb = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var c in arg)
        {
            if (c == '\\') { backslashes++; continue; }
            if (c == '"') { sb.Append('\\', backslashes * 2 + 1).Append('"'); backslashes = 0; continue; }
            sb.Append('\\', backslashes).Append(c);
            backslashes = 0;
        }
        sb.Append('\\', backslashes * 2).Append('"');
        var quoted = sb.ToString();
        var escaped = new StringBuilder();
        foreach (var c in quoted)
        {
            if ("()%!^\"<>&|".Contains(c)) escaped.Append('^');
            escaped.Append(c);
        }
        return escaped.ToString();
    }
}

/// <summary>Ends the server (and anything it started) when the proxy exits, however it exits. Uses a documented Windows job object.</summary>
[SupportedOSPlatform("windows")]
public sealed class KillOnCloseJob : IDisposable
{
    private readonly IntPtr _handle;

    public KillOnCloseJob()
    {
        _handle = CreateJobObjectW(IntPtr.Zero, null);
        if (_handle == IntPtr.Zero) throw new Win32Exception();
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        var size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, ptr, false);
            if (!SetInformationJobObject(_handle, JobObjectExtendedLimitInformation, ptr, (uint)size)) throw new Win32Exception();
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public void Add(Process p)
    {
        if (!AssignProcessToJobObject(_handle, p.Handle)) throw new Win32Exception();
    }

    public void Dispose() => CloseHandle(_handle);

    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObjectW(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
