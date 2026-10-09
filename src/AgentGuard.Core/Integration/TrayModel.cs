using System.Text.Json;

namespace AgentGuard.Core.Integration;

public enum TrayLevel
{
    /// <summary>Connected, enforcing, nothing waiting.</summary>
    Protected,
    /// <summary>Monitor mode: recording only.</summary>
    Monitoring,
    /// <summary>Something needs the user: pending approvals or open high-severity alerts.</summary>
    Attention,
    /// <summary>Kill switch engaged.</summary>
    Stopped,
    /// <summary>The service cannot be reached.</summary>
    Disconnected,
}

public sealed record TrayState(TrayLevel Level, string Tooltip, string Mode, bool ProtectionOn, bool KillSwitch, int PendingApprovals, int OpenAlerts);

/// <summary>Presentation logic for the tray app, kept free of UI types so it can be tested anywhere.</summary>
public static class TrayModel
{
    public static TrayState Disconnected(string why) =>
        new(TrayLevel.Disconnected, Clip("AgentGuard: not connected (" + why + ")"), "unknown", false, false, 0, 0);

    public static TrayState FromStatus(JsonElement status)
    {
        var mode = status.TryGetProperty("mode", out var m) ? m.GetString() ?? "enforce" : "enforce";
        var kill = status.TryGetProperty("killSwitch", out var k) && k.GetProperty("engaged").GetBoolean();
        var counts = status.GetProperty("counts");
        var pending = counts.GetProperty("pendingApprovals").GetInt32();
        var alerts = counts.GetProperty("openAlerts").GetInt32();
        var blocked = counts.GetProperty("blockedToday").GetInt32();
        var agents = counts.GetProperty("activeAgents").GetInt32();

        var level = kill ? TrayLevel.Stopped
            : pending > 0 ? TrayLevel.Attention
            : mode == "monitor" ? TrayLevel.Monitoring
            : TrayLevel.Protected;
        var head = level switch
        {
            TrayLevel.Stopped => "AgentGuard: kill switch engaged",
            TrayLevel.Attention => $"AgentGuard: {pending} approval{(pending == 1 ? "" : "s")} waiting",
            TrayLevel.Monitoring => "AgentGuard: monitoring only",
            _ => mode == "strict" ? "AgentGuard: protecting (strict)" : "AgentGuard: protecting",
        };
        // NotifyIcon tooltips are limited to 127 characters.
        var tip = $"{head}\n{agents} active agent{(agents == 1 ? "" : "s")} · {blocked} blocked today · {alerts} open alert{(alerts == 1 ? "" : "s")}";
        return new TrayState(level, Clip(tip), mode, mode != "monitor", kill, pending, alerts);
    }

    private static string Clip(string s) => s.Length <= 127 ? s : s[..126] + "…";

    /// <summary>A short human sentence for an approval: "Claude Code wants to run: git push origin main".</summary>
    public static string Describe(string agentName, string action, string target)
    {
        var verb = action switch
        {
            Actions.ShellExec or Actions.ProcessStart => "run",
            Actions.FileRead => "read",
            Actions.FileWrite => "write to",
            Actions.FileDelete => "delete",
            Actions.NetConnect => "connect to",
            Actions.McpCall => "use the tool",
            _ => action,
        };
        return $"{agentName} wants to {verb}:";
    }

    public static string Countdown(DateTimeOffset expiresAt, DateTimeOffset now)
    {
        var left = expiresAt - now;
        if (left <= TimeSpan.Zero) return "expired";
        return left.TotalSeconds < 60 ? $"{(int)Math.Ceiling(left.TotalSeconds)} s left" : $"{(int)left.TotalMinutes} min {left.Seconds:00} s left";
    }

    public static string DashboardOrigin(int port) => $"http://127.0.0.1:{port}";

    /// <summary>Only the local dashboard may load inside the embedded browser; anything else opens in the user's browser.</summary>
    public static bool IsDashboardUrl(string url, int port) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u)
        && u.Scheme == Uri.UriSchemeHttp
        && (u.Host == "127.0.0.1" || u.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        && u.Port == port;

    /// <summary>Script injected into the dashboard so it is signed in; it refuses to run on any other origin.</summary>
    public static string TokenScript(string token, int port) =>
        $"if (location.origin === {JsonSerializer.Serialize(DashboardOrigin(port))}) {{ window.__AGENTGUARD_TOKEN__ = {JsonSerializer.Serialize(token)}; }}";
}
