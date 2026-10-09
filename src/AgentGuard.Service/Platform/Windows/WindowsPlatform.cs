using System.Management;
using System.Runtime.Versioning;
using AgentGuard.Core.Discovery;

namespace AgentGuard.Service.Platform.Windows;

/// <summary>Read-only process inventory through WMI (the same data Task Manager shows).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessSource : IProcessSource
{
    public IReadOnlyList<ProcessInfo> Snapshot()
    {
        var list = new List<ProcessInfo>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process");
        using var results = searcher.Get();
        foreach (ManagementObject mo in results)
        {
            using (mo)
            {
                try
                {
                    var pid = Convert.ToInt32(mo["ProcessId"]);
                    var ppid = Convert.ToInt32(mo["ParentProcessId"]);
                    var name = mo["Name"] as string ?? "";
                    var exe = mo["ExecutablePath"] as string;
                    var cmd = mo["CommandLine"] as string;
                    var created = mo["CreationDate"] is string cd
                        ? new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(cd)).ToUniversalTime()
                        : DateTimeOffset.MinValue;
                    list.Add(new ProcessInfo(pid, ppid == 0 ? null : ppid, name, exe, cmd ?? name, created));
                }
                catch (Exception ex) when (ex is ManagementException or FormatException or InvalidCastException) { }
            }
        }
        return list;
    }
}
