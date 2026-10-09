using System.Threading;
using System.Windows;

namespace AgentGuard.Tray;

/// <summary>
/// Tray app entry point. One instance per user session; starting it again (for example from the Start menu with
/// <c>--open</c>) asks the running instance to show the dashboard instead.
/// </summary>
public partial class App : System.Windows.Application
{
    private const string InstanceName = @"Local\AgentGuard.Tray";
    private const string ShowEventName = @"Local\AgentGuard.Tray.Show";

    private Mutex? _single;
    private EventWaitHandle? _showEvent;
    private TrayController? _tray;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _single = new Mutex(initiallyOwned: true, InstanceName, out var first);
        if (!first)
        {
            if (EventWaitHandle.TryOpenExisting(ShowEventName, out var existing)) { existing.Set(); existing.Dispose(); }
            Shutdown();
            return;
        }

        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        var watcher = new Thread(() =>
        {
            while (_showEvent.WaitOne()) Dispatcher.BeginInvoke(() => _tray?.OpenDashboard());
        }) { IsBackground = true, Name = "AgentGuard.Tray.Show" };
        watcher.Start();

        _tray = new TrayController(Dispatcher);
        if (e.Args.Contains("--open")) Dispatcher.BeginInvoke(async () =>
        {
            await Task.Delay(1500); // give the connection a moment to fetch the token
            _tray.OpenDashboard();
        });
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        _showEvent?.Dispose();
        try { _single?.ReleaseMutex(); } catch (ApplicationException) { }
        _single?.Dispose();
        base.OnExit(e);
    }
}
