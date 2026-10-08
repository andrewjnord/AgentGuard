namespace AgentGuard.Core;

public sealed class AgentGuardSettings
{
    public const string MaskedSecret = "********";

    public int RetentionDays { get; set; } = 30;
    public string FailMode { get; set; } = "closed";
    public bool AutoSuspendOnDetectBlock { get; set; } = true;
    public int ApprovalTimeoutSeconds { get; set; } = 60;
    public ExportSettings Exports { get; set; } = new();
    public RedactionSettings Redaction { get; set; } = new();

    public AgentGuardSettings Masked()
    {
        var copy = Json.Deserialize<AgentGuardSettings>(Json.Serialize(this))!;
        if (!string.IsNullOrEmpty(copy.Exports.Splunk.Token)) copy.Exports.Splunk.Token = MaskedSecret;
        return copy;
    }

    public IEnumerable<string> Validate()
    {
        if (RetentionDays is < 1 or > 3650) yield return "retentionDays must be between 1 and 3650.";
        if (FailMode is not ("closed" or "open")) yield return "failMode must be 'closed' or 'open'.";
        if (ApprovalTimeoutSeconds is < 5 or > 3600) yield return "approvalTimeoutSeconds must be between 5 and 3600.";
        if (Exports.Splunk.Enabled && !Uri.TryCreate(Exports.Splunk.Url, UriKind.Absolute, out _)) yield return "Splunk URL is not a valid absolute URL.";
        if (Exports.Syslog.Enabled && (string.IsNullOrWhiteSpace(Exports.Syslog.Host) || Exports.Syslog.Port is < 1 or > 65535)) yield return "Syslog host and port are required.";
        if (Exports.Syslog.Protocol is not ("udp" or "tcp")) yield return "Syslog protocol must be 'udp' or 'tcp'.";
        if (Exports.JsonFile.Enabled && string.IsNullOrWhiteSpace(Exports.JsonFile.Directory)) yield return "JSON export directory is required.";
        foreach (var p in Redaction.Patterns)
        {
            string? error = null;
            try { _ = new System.Text.RegularExpressions.Regex(p); } catch (ArgumentException ex) { error = $"Invalid redaction pattern '{p}': {ex.Message}"; }
            if (error is not null) yield return error;
        }
    }
}

public sealed class ExportSettings
{
    public SplunkSettings Splunk { get; set; } = new();
    public SyslogSettings Syslog { get; set; } = new();
    public JsonFileSettings JsonFile { get; set; } = new();
}

public sealed class SplunkSettings
{
    public bool Enabled { get; set; }
    public string Url { get; set; } = "https://splunk.example.com:8088/services/collector/event";
    public string? Token { get; set; }
    public string Index { get; set; } = "main";
    public string Sourcetype { get; set; } = "agentguard:ocsf";
    public bool VerifyTls { get; set; } = true;
}

public sealed class SyslogSettings
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 514;
    public string Protocol { get; set; } = "udp";
}

public sealed class JsonFileSettings
{
    public bool Enabled { get; set; }
    public string Directory { get; set; } = "";
}

public sealed class RedactionSettings
{
    public List<string> Patterns { get; set; } = new()
    {
        @"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+",
        @"(?i)bearer\s+[A-Za-z0-9._\-]+",
        @"sk-[A-Za-z0-9_\-]{16,}",
        @"ghp_[A-Za-z0-9]{20,}",
        @"AKIA[0-9A-Z]{16}",
    };
}
