using System.Text;
using System.Text.Json.Nodes;
using AgentGuard.Core.Policy;

namespace AgentGuard.Core.Export;

/// <summary>Maps AgentGuard events to the Open Cybersecurity Schema Framework (OCSF 1.1) so any SIEM can ingest them without custom parsing.</summary>
public static class OcsfMapper
{
    public const string SchemaVersion = "1.1.0";

    public static JsonObject Map(AgentEvent e, string hostname, string productVersion)
    {
        var (classUid, className, categoryUid, categoryName, activityId, activityName) = Classify(e.Action);
        var (dispositionId, disposition) = Disposition(e);

        var o = new JsonObject
        {
            ["class_uid"] = classUid,
            ["class_name"] = className,
            ["category_uid"] = categoryUid,
            ["category_name"] = categoryName,
            ["activity_id"] = activityId,
            ["activity_name"] = activityName,
            ["type_uid"] = classUid * 100 + activityId,
            ["time"] = e.Ts.ToUnixTimeMilliseconds(),
            ["severity_id"] = SeverityId(e.Severity),
            ["severity"] = Capitalize(e.Severity.ToString()),
            ["status_id"] = e.Verdict == Verdict.Block ? 2 : 1,
            ["status"] = e.Verdict == Verdict.Block ? "Failure" : "Success",
            ["disposition_id"] = dispositionId,
            ["disposition"] = disposition,
            ["message"] = Message(e),
            ["metadata"] = new JsonObject
            {
                ["version"] = SchemaVersion,
                ["uid"] = e.Hash,
                ["sequence"] = e.Id,
                ["product"] = new JsonObject
                {
                    ["name"] = "AgentGuard",
                    ["vendor_name"] = "AgentGuard",
                    ["version"] = productVersion,
                },
                ["labels"] = new JsonArray("ai-agent", e.Source),
            },
            ["device"] = new JsonObject
            {
                ["hostname"] = hostname,
                ["type_id"] = 2,
                ["type"] = "Desktop",
                ["os"] = new JsonObject { ["name"] = OperatingSystem.IsWindows() ? "Windows" : Environment.OSVersion.Platform.ToString(), ["type_id"] = OperatingSystem.IsWindows() ? 100 : 200 },
            },
            ["actor"] = new JsonObject
            {
                ["app_name"] = e.AgentName,
                ["app_uid"] = e.AgentId,
                ["process"] = e.Pid is null ? null : new JsonObject { ["pid"] = e.Pid },
            },
        };

        switch (classUid)
        {
            case 1001:
                var path = e.Target;
                o["file"] = new JsonObject { ["path"] = path, ["name"] = Path.GetFileName(path.Replace('\\', '/')), ["type_id"] = 1 };
                break;
            case 1007:
                o["process"] = new JsonObject { ["cmd_line"] = e.Target };
                break;
            case 4001:
                var host = PolicyEngine.HostOf(new PolicyInput(e.AgentId, e.Action, e.Target, e.Details));
                var endpoint = new JsonObject { ["hostname"] = host };
                if (e.Details.TryGetValue("ip", out var ip) && ip is string ips) endpoint["ip"] = ips;
                if (e.Details.TryGetValue("port", out var port) && port is long p) endpoint["port"] = p;
                o["dst_endpoint"] = endpoint;
                break;
            case 6003:
                var slash = e.Target.IndexOf('/');
                o["api"] = new JsonObject
                {
                    ["operation"] = slash >= 0 ? e.Target[(slash + 1)..] : e.Target,
                    ["service"] = new JsonObject { ["name"] = slash >= 0 ? e.Target[..slash] : e.AgentId },
                };
                break;
        }

        o["unmapped"] = new JsonObject
        {
            ["agentguard"] = new JsonObject
            {
                ["event_id"] = e.Id,
                ["agent_id"] = e.AgentId,
                ["action"] = e.Action,
                ["target"] = e.Target,
                ["verdict"] = e.Verdict.ToString().ToLowerInvariant(),
                ["rule_id"] = e.RuleId,
                ["source"] = e.Source,
                ["enforced"] = e.Enforced,
                ["hash"] = e.Hash,
                ["details"] = JsonNode.Parse(Json.Serialize(e.Details)),
            },
        };
        return o;
    }

    private static (int, string, int, string, int, string) Classify(string action) => action switch
    {
        Actions.FileRead => (1001, "File System Activity", 1, "System Activity", 2, "Read"),
        Actions.FileWrite => (1001, "File System Activity", 1, "System Activity", 3, "Update"),
        Actions.FileDelete => (1001, "File System Activity", 1, "System Activity", 4, "Delete"),
        Actions.ProcessStart or Actions.ShellExec => (1007, "Process Activity", 1, "System Activity", 1, "Launch"),
        Actions.NetConnect => (4001, "Network Activity", 4, "Network Activity", 1, "Open"),
        Actions.McpCall => (6003, "API Activity", 6, "Application Activity", 99, "Tool Call"),
        _ => (0, "Base Event", 0, "Uncategorized", 99, action),
    };

    private static (int, string) Disposition(AgentEvent e) => e.Verdict switch
    {
        Verdict.Block when e.Enforced => (2, "Blocked"),
        Verdict.Block => (15, "Detected"),
        Verdict.Ask => (99, "Approval Required"),
        Verdict.Allow => (1, "Allowed"),
        _ => (17, "Logged"),
    };

    private static int SeverityId(Severity s) => s switch
    {
        Severity.Info => 1,
        Severity.Low => 2,
        Severity.Medium => 3,
        Severity.High => 4,
        Severity.Critical => 5,
        _ => 0,
    };

    public static string Message(AgentEvent e)
    {
        var verdict = e.Verdict switch
        {
            Verdict.Block => e.Enforced ? "blocked" : "flagged (not prevented)",
            Verdict.Ask => "held for approval",
            Verdict.Allow => "allowed",
            _ => "logged",
        };
        return $"{e.AgentName} {e.Action} {Truncate(e.Target, 200)} — {verdict}" + (e.RuleId is null ? "" : $" by rule {e.RuleId}");
    }

    private static string Capitalize(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
    internal static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}

/// <summary>ArcSight Common Event Format, for syslog-based SIEMs.</summary>
public static class Cef
{
    public static string Format(AgentEvent e, string hostname, string productVersion)
    {
        var sev = e.Severity switch
        {
            Severity.Info => 1,
            Severity.Low => 3,
            Severity.Medium => 5,
            Severity.High => 8,
            Severity.Critical => 10,
            _ => 0,
        };
        var name = OcsfMapper.Message(e);
        var ext = new StringBuilder();
        void Add(string k, string? v)
        {
            if (string.IsNullOrEmpty(v)) return;
            if (ext.Length > 0) ext.Append(' ');
            ext.Append(k).Append('=').Append(EscapeExtension(v));
        }
        Add("rt", e.Ts.ToUnixTimeMilliseconds().ToString());
        Add("dvchost", hostname);
        Add("act", e.Verdict.ToString().ToLowerInvariant());
        Add("outcome", e.Enforced ? "enforced" : "observed");
        Add("spid", e.Pid?.ToString());
        Add("sproc", e.AgentName);
        Add("cs1Label", "agentId"); Add("cs1", e.AgentId);
        Add("cs2Label", "ruleId"); Add("cs2", e.RuleId);
        Add("cs3Label", "source"); Add("cs3", e.Source);
        Add("cs4Label", "hash"); Add("cs4", e.Hash);
        Add("cn1Label", "eventId"); Add("cn1", e.Id.ToString());
        Add("msg", OcsfMapper.Truncate(e.Target, 1023));
        if (e.Action.StartsWith("file.", StringComparison.Ordinal)) Add("filePath", e.Target);
        if (e.Action is Actions.ShellExec or Actions.ProcessStart) Add("cs5Label", "commandLine");
        if (e.Action is Actions.ShellExec or Actions.ProcessStart) Add("cs5", OcsfMapper.Truncate(e.Target, 1023));
        if (e.Action == Actions.NetConnect) Add("dhost", PolicyEngine.HostOf(e.Target));

        return $"CEF:0|AgentGuard|AgentGuard|{EscapeHeader(productVersion)}|{EscapeHeader(e.Action)}|{EscapeHeader(OcsfMapper.Truncate(name, 512))}|{sev}|{ext}";
    }

    public static string EscapeHeader(string s) => s.Replace("\\", "\\\\").Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");
    public static string EscapeExtension(string s) => s.Replace("\\", "\\\\").Replace("=", "\\=").Replace("\r", "\\r").Replace("\n", "\\n");
}
