using System.Diagnostics;
using System.IO;
using System.Windows;
using AgentGuard.Core.Integration;
using Microsoft.Web.WebView2.Core;

namespace AgentGuard.Tray;

/// <summary>
/// Hosts the dashboard in WebView2, signed in with the admin token (injected only on the dashboard's own origin).
/// The embedded browser stays on the local dashboard; any other link opens in the user's default browser.
/// </summary>
public partial class DashboardWindow : Window
{
    private readonly ServiceConnection _service;
    private string? _scriptId;
    private string _route;
    private bool _ready;

    public DashboardWindow(ServiceConnection service, string route = "")
    {
        InitializeComponent();
        _service = service;
        _route = route;
        Loaded += async (_, _) => await InitAsync();
    }

    private string Url => TrayModel.DashboardOrigin(_service.Port) + "/" + (_route.Length > 0 ? "#/" + _route : "");

    private async Task InitAsync()
    {
        try
        {
            var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgentGuard", "WebView2");
            var env = await CoreWebView2Environment.CreateAsync(null, dataDir);
            await Web.EnsureCoreWebView2Async(env);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            // No WebView2 runtime: fall back to the default browser, handing over the token in the URL fragment (never sent to the server).
            OpenExternal(Url.Split('#')[0] + "#token=" + Uri.EscapeDataString(_service.Token ?? ""));
            Close();
            return;
        }

        var core = Web.CoreWebView2;
        var s = core.Settings;
        s.IsPasswordAutosaveEnabled = false;
        s.IsGeneralAutofillEnabled = false;
        s.IsStatusBarEnabled = false;
#if !DEBUG
        s.AreDevToolsEnabled = false;
#endif
        core.NavigationStarting += (_, e) =>
        {
            if (TrayModel.IsDashboardUrl(e.Uri, _service.Port)) return;
            e.Cancel = true;
            OpenExternal(e.Uri);
        };
        core.NewWindowRequested += (_, e) =>
        {
            e.Handled = true;
            if (TrayModel.IsDashboardUrl(e.Uri, _service.Port)) core.Navigate(e.Uri);
            else OpenExternal(e.Uri);
        };
        core.NavigationCompleted += (_, e) => Status.Visibility = e.IsSuccess ? Visibility.Collapsed : Visibility.Visible;
        await InjectTokenAsync();
        _ready = true;
        core.Navigate(Url);
    }

    private async Task InjectTokenAsync()
    {
        if (_scriptId is not null) Web.CoreWebView2.RemoveScriptToExecuteOnDocumentCreated(_scriptId);
        _scriptId = _service.Token is { } t ? await Web.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(TrayModel.TokenScript(t, _service.Port)) : null;
    }

    /// <summary>The service restarted and rotated its token: re-inject and reload.</summary>
    public async Task OnTokenChangedAsync()
    {
        if (!_ready) return;
        await InjectTokenAsync();
        Web.CoreWebView2.Reload();
    }

    public void Show(string route)
    {
        if (_ready && route != _route)
        {
            _route = route;
            Web.CoreWebView2.Navigate(Url);
        }
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Show();
        Activate();
    }

    private static void OpenExternal(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps)) return;
        try { Process.Start(new ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true }); } catch { }
    }
}
