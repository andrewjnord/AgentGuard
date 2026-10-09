using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using AgentGuard.Core.Integration;
using Forms = System.Windows.Forms;

namespace AgentGuard.Tray;

/// <summary>The notification-area icon and its menu: status at a glance, quick protection on/off, kill switch, approvals and the dashboard.</summary>
public sealed class TrayController : IDisposable
{
    private readonly Dispatcher _ui;
    private readonly ServiceConnection _service = new();
    private readonly Forms.NotifyIcon _icon = new();
    private readonly Forms.ToolStripMenuItem _header = new() { Enabled = false };
    private readonly Forms.ToolStripMenuItem _approvals = new("Approvals");
    private readonly Forms.ToolStripMenuItem _protection = new("Protection on") { CheckOnClick = false };
    private readonly Forms.ToolStripMenuItem _strict = new("Strict mode");
    private readonly Forms.ToolStripMenuItem _killSwitch = new("Emergency stop (kill switch)…");
    private readonly Dictionary<string, ApprovalWindow> _popups = new();
    private DashboardWindow? _dashboard;
    private TrayState _state = TrayModel.Disconnected("starting");
    private string _lastEnforcingMode = "enforce";

    public TrayController(Dispatcher ui)
    {
        _ui = ui;
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(_header);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(new Forms.ToolStripMenuItem("Open dashboard", null, (_, _) => OpenDashboard()));
        menu.Items.Add(_approvals);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_protection);
        menu.Items.Add(_strict);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_killSwitch);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(new Forms.ToolStripMenuItem("Close tray icon", null, (_, _) => System.Windows.Application.Current.Shutdown()));
        _approvals.Click += (_, _) => OpenDashboard("approvals");
        _protection.Click += async (_, _) => await ToggleProtectionAsync();
        _strict.Click += async (_, _) => await SetModeAsync(_state.Mode == "strict" ? "enforce" : "strict");
        _killSwitch.Click += async (_, _) => await ToggleKillSwitchAsync();

        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => OpenDashboard();
        _icon.BalloonTipClicked += (_, _) => OpenDashboard(_state.PendingApprovals > 0 ? "approvals" : "alerts");

        _service.StateChanged += s => _ui.BeginInvoke(() => Apply(s));
        _service.ApprovalChanged += a => _ui.BeginInvoke(() => OnApproval(a));
        _service.AlertRaised += a => _ui.BeginInvoke(() => OnAlert(a));
        _service.TokenChanged += _ => _ui.BeginInvoke(async () => { if (_dashboard is not null) await _dashboard.OnTokenChangedAsync(); });

        Apply(_state);
        _icon.Visible = true;
        _service.Start();
    }

    private void Apply(TrayState s)
    {
        var wasKill = _state.KillSwitch;
        _state = s;
        if (s.ProtectionOn && s.Mode != "unknown") _lastEnforcingMode = s.Mode;
        _icon.Icon = TrayIcons.For(s.Level);
        _icon.Text = s.Tooltip;
        _header.Text = s.Tooltip.Split('\n')[0];
        var connected = s.Level != TrayLevel.Disconnected;
        _protection.Enabled = _strict.Enabled = _killSwitch.Enabled = _approvals.Enabled = connected;
        _protection.Checked = s.ProtectionOn;
        _strict.Checked = s.Mode == "strict";
        _approvals.Text = s.PendingApprovals > 0 ? $"Approvals ({s.PendingApprovals} waiting)" : "Approvals";
        _killSwitch.Text = s.KillSwitch ? "Release kill switch" : "Emergency stop (kill switch)…";
        if (s.KillSwitch && !wasKill && connected)
            _icon.ShowBalloonTip(5000, "AgentGuard kill switch engaged", "Every action checked by AgentGuard is blocked until you release it.", Forms.ToolTipIcon.Warning);
    }

    private async Task ToggleProtectionAsync()
    {
        if (_state.ProtectionOn)
        {
            var ok = System.Windows.MessageBox.Show(
                "Turn protection off?\n\nAgentGuard will keep recording what AI agents do, but it will not block or hold anything until you turn protection back on.",
                "AgentGuard", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);
            if (ok != MessageBoxResult.OK) return;
            await SetModeAsync("monitor");
        }
        else await SetModeAsync(_lastEnforcingMode is "enforce" or "strict" ? _lastEnforcingMode : "enforce");
    }

    private async Task SetModeAsync(string mode)
    {
        try { Apply(TrayModel.FromStatus(await _service.SetModeAsync(mode))); }
        catch (Exception ex) { Fail("Could not change the protection mode", ex); }
    }

    private async Task ToggleKillSwitchAsync()
    {
        try
        {
            if (_state.KillSwitch)
            {
                Apply(TrayModel.FromStatus(await _service.KillSwitchAsync("release")));
                return;
            }
            var ok = System.Windows.MessageBox.Show(
                "Engage the kill switch?\n\nEvery action checked by AgentGuard will be blocked and open approvals are denied. AI agent processes are also suspended on PCs where process control is available. Release it from this menu.",
                "AgentGuard emergency stop", MessageBoxButton.OKCancel, MessageBoxImage.Stop, MessageBoxResult.Cancel);
            if (ok == MessageBoxResult.OK) Apply(TrayModel.FromStatus(await _service.KillSwitchAsync("engage")));
        }
        catch (Exception ex) { Fail("Could not change the kill switch", ex); }
    }

    private void OnApproval(JsonElement a)
    {
        var id = a.GetProperty("id").GetString()!;
        var status = a.GetProperty("status").GetString();
        if (status != "pending")
        {
            if (_popups.Remove(id, out var w)) w.Close();
            return;
        }
        if (_popups.ContainsKey(id)) return;
        var window = new ApprovalWindow(a, _service);
        window.Closed += (_, _) => { _popups.Remove(id); Restack(); };
        _popups[id] = window;
        window.Show();
        Restack();
        System.Media.SystemSounds.Asterisk.Play();
    }

    /// <summary>Stacks pop-ups upward from the bottom-right corner of the work area.</summary>
    private void Restack()
    {
        var area = SystemParameters.WorkArea;
        var bottom = area.Bottom;
        foreach (var w in _popups.Values)
        {
            w.UpdateLayout();
            var h = w.ActualHeight > 0 ? w.ActualHeight : 220;
            w.Left = area.Right - w.Width;
            w.Top = bottom - h;
            bottom -= h;
            if (bottom < area.Top + 100) break;
        }
    }

    private void OnAlert(JsonElement a)
    {
        var severity = a.GetProperty("severity").GetString();
        if (severity is not ("high" or "critical") || a.GetProperty("status").GetString() != "open") return;
        _icon.ShowBalloonTip(6000, severity == "critical" ? "AgentGuard: critical alert" : "AgentGuard alert",
            a.GetProperty("title").GetString() ?? "", severity == "critical" ? Forms.ToolTipIcon.Error : Forms.ToolTipIcon.Warning);
    }

    public void OpenDashboard(string route = "")
    {
        if (_service.Token is null)
        {
            System.Windows.MessageBox.Show("AgentGuard is not connected to its service yet. Check that the AgentGuard service is running.", "AgentGuard",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (_dashboard is null)
        {
            _dashboard = new DashboardWindow(_service, route);
            _dashboard.Closed += (_, _) => _dashboard = null;
        }
        _dashboard.Show(route);
    }

    private void Fail(string what, Exception ex) =>
        _icon.ShowBalloonTip(5000, "AgentGuard", $"{what}: {ex.Message}", Forms.ToolTipIcon.Error);

    public void Dispose()
    {
        foreach (var w in _popups.Values.ToList()) w.Close();
        _icon.Visible = false;
        _icon.Dispose();
        _service.Dispose();
    }
}
