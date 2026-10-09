using System.Text.Json;
using AgentGuard.Core.Integration;
using AgentGuard.Service.Tests;

namespace AgentGuard.Tools.Tests;

public class TrayModelTests
{
    private static JsonElement Status(string mode = "enforce", bool kill = false, int pending = 0, int alerts = 0, int blocked = 3, int active = 2) =>
        JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            mode,
            killSwitch = new { engaged = kill },
            counts = new { pendingApprovals = pending, openAlerts = alerts, blockedToday = blocked, activeAgents = active },
        })).RootElement;

    [Fact]
    public void LevelsFollowStatusPriority()
    {
        Assert.Equal(TrayLevel.Protected, TrayModel.FromStatus(Status()).Level);
        Assert.Equal(TrayLevel.Monitoring, TrayModel.FromStatus(Status("monitor")).Level);
        Assert.False(TrayModel.FromStatus(Status("monitor")).ProtectionOn);
        Assert.Equal(TrayLevel.Attention, TrayModel.FromStatus(Status("monitor", pending: 1)).Level);
        Assert.Equal(TrayLevel.Stopped, TrayModel.FromStatus(Status(kill: true, pending: 4)).Level);
        Assert.Equal(TrayLevel.Disconnected, TrayModel.Disconnected("x").Level);
    }

    [Fact]
    public void TooltipFitsTheNotifyIconLimit()
    {
        var s = TrayModel.FromStatus(Status("strict", pending: 0, alerts: 1, blocked: 12345, active: 1));
        Assert.StartsWith("AgentGuard: protecting (strict)", s.Tooltip);
        Assert.Contains("1 active agent ·", s.Tooltip);
        Assert.Contains("1 open alert", s.Tooltip);
        Assert.True(s.Tooltip.Length <= 127);
        Assert.True(TrayModel.Disconnected(new string('x', 300)).Tooltip.Length <= 127);
        Assert.Equal("AgentGuard: 2 approvals waiting", TrayModel.FromStatus(Status(pending: 2)).Tooltip.Split('\n')[0]);
    }

    [Fact]
    public async Task WorksWithTheRealStatusPayload()
    {
        using var f = new ServiceFixture();
        var s = TrayModel.FromStatus(await f.Client().GetJson("/api/v1/status"));
        Assert.Equal(TrayLevel.Protected, s.Level);
        Assert.Equal("enforce", s.Mode);
    }

    [Theory]
    [InlineData("http://127.0.0.1:47823/", true)]
    [InlineData("http://127.0.0.1:47823/#/approvals", true)]
    [InlineData("http://localhost:47823/api/v1/status", true)]
    [InlineData("https://127.0.0.1:47823/", false)]
    [InlineData("http://127.0.0.1:8080/", false)]
    [InlineData("http://evil.example/?u=127.0.0.1:47823", false)]
    [InlineData("http://127.0.0.1.evil.example:47823/", false)]
    [InlineData("file:///C:/Windows/win.ini", false)]
    [InlineData("javascript:alert(1)", false)]
    public void OnlyTheLocalDashboardLoadsInTheEmbeddedBrowser(string url, bool allowed) =>
        Assert.Equal(allowed, TrayModel.IsDashboardUrl(url, 47823));

    [Fact]
    public void TokenScriptIsOriginBoundAndEscaped()
    {
        var script = TrayModel.TokenScript("ab\"c</script>", 47823);
        Assert.StartsWith("if (location.origin === \"http://127.0.0.1:47823\")", script);
        Assert.Contains("window.__AGENTGUARD_TOKEN__ = \"ab\\u0022c\\u003C/script\\u003E\"", script);
    }

    [Fact]
    public void ApprovalText()
    {
        Assert.Equal("Claude Code wants to run:", TrayModel.Describe("Claude Code", "shell.exec", "git push"));
        Assert.Equal("MCP: github wants to use the tool:", TrayModel.Describe("MCP: github", "mcp.call", "github/push"));
        var now = DateTimeOffset.UtcNow;
        Assert.Equal("30 s left", TrayModel.Countdown(now.AddSeconds(29.5), now));
        Assert.Equal("2 min 05 s left", TrayModel.Countdown(now.AddSeconds(125), now));
        Assert.Equal("expired", TrayModel.Countdown(now.AddSeconds(-1), now));
    }
}

public class TrayBuildTests
{
    /// <summary>Regression: with invariant globalization WPF crashed the first time a window drew text (the approval pop-up).</summary>
    [Fact]
    public void TrayIsNotBuiltWithInvariantGlobalization()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AgentGuard.sln"))) dir = dir.Parent;
        Assert.NotNull(dir);
        var csproj = File.ReadAllText(Path.Combine(dir!.FullName, "src", "AgentGuard.Tray", "AgentGuard.Tray.csproj"));
        Assert.DoesNotContain("<InvariantGlobalization>true", csproj);
        var publish = File.ReadAllText(Path.Combine(dir.FullName, "build", "publish.ps1"));
        Assert.DoesNotContain("InvariantGlobalization=true", publish);
    }
}
