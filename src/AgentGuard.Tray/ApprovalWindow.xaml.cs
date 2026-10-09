using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using AgentGuard.Core.Integration;

namespace AgentGuard.Tray;

/// <summary>A pop-up for one pending approval. It closes itself when the approval is answered anywhere or expires.</summary>
public partial class ApprovalWindow : Window
{
    private readonly ServiceConnection _service;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(500) };
    private readonly DateTimeOffset _expiresAt;

    public string ApprovalId { get; }

    public ApprovalWindow(JsonElement approval, ServiceConnection service)
    {
        InitializeComponent();
        _service = service;
        ApprovalId = approval.GetProperty("id").GetString()!;
        _expiresAt = DateTimeOffset.Parse(approval.GetProperty("expiresAt").GetString()!);
        var agent = approval.GetProperty("agentName").GetString() ?? "";
        var action = approval.GetProperty("action").GetString() ?? "";
        Headline.Text = TrayModel.Describe(agent, action, "");
        Target.Text = approval.GetProperty("target").GetString();
        Rule.Text = approval.GetProperty("ruleId").ValueKind == JsonValueKind.String
            ? $"Policy rule: {approval.GetProperty("ruleId").GetString()}" : "";
        _timer.Tick += (_, _) => Tick();
        Tick();
        _timer.Start();
    }

    private void Tick()
    {
        Countdown.Text = TrayModel.Countdown(_expiresAt, DateTimeOffset.UtcNow);
        if (DateTimeOffset.UtcNow > _expiresAt.AddSeconds(2)) Close();
    }

    private async void Answer(string decision)
    {
        SetEnabled(false);
        try
        {
            await _service.DecideAsync(ApprovalId, decision);
            Close();
        }
        catch (AgentGuardApiException ex) when (ex.StatusCode is 404 or 409)
        {
            Close(); // already answered elsewhere or expired
        }
        catch (Exception ex)
        {
            ErrorText.Text = "Could not send the answer: " + ex.Message;
            ErrorText.Visibility = Visibility.Visible;
            SetEnabled(true);
        }
    }

    private void SetEnabled(bool on) => OnceButton.IsEnabled = AlwaysButton.IsEnabled = DenyButton.IsEnabled = on;

    private void Once_Click(object sender, RoutedEventArgs e) => Answer("allow_once");
    private void Always_Click(object sender, RoutedEventArgs e) => Answer("allow_always");
    private void Deny_Click(object sender, RoutedEventArgs e) => Answer("deny");

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }
}
