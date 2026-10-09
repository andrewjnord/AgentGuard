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

    public static string LogPath { get; } = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgentGuard", "tray.log");

    /// <summary>Appends to %LOCALAPPDATA%\AgentGuard\tray.log (kept under 1 MB).</summary>
    public static void Log(string message)
    {
        try
        {
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(LogPath)!);
            var info = new System.IO.FileInfo(LogPath);
            if (info.Exists && info.Length > 1_000_000) info.Delete();
            System.IO.File.AppendAllText(LogPath, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} {message}{Environment.NewLine}");
        }
        catch { }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // A UI error must not take the tray (and the approval prompts) down with it: log it and carry on.
        DispatcherUnhandledException += (_, args) =>
        {
            Log("UI error: " + args.Exception);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) => Log("Fatal error: " + args.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (_, args) => { Log("Background error: " + args.Exception); args.SetObserved(); };
        _single = new Mutex(initiallyOwned: true, InstanceName, out var first);
        if (!first)
        {
            // The installer relaunches the tray with --background: if one is already running, leave it alone.
            // Any other second launch (Start menu shortcut) asks the running copy to open the dashboard.
            if (!e.Args.Contains("--background") && EventWaitHandle.TryOpenExisting(ShowEventName, out var existing))
            {
                existing.Set();
                existing.Dispose();
            }
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
