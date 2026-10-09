namespace AgentGuard.Service.Platform.Windows;

/// <summary>Placeholder until the Windows adapters land (deliverable 6).</summary>
public sealed class WindowsEnforcementAdapters : IEnforcementAdapters
{
    public WindowsEnforcementAdapters(AgentGuardOptions options) { }
    public IProcessController? Processes => null;
    public INetworkBlocker? Network => null;
    public Func<ITelemetrySource>? TelemetryFactory => null;
    public IFileTrust? FileTrust => null;
}
