using System.Text.RegularExpressions;

namespace AgentGuard.Core.Policy;

public sealed class PolicyDocument
{
    public int Version { get; set; } = 1;
    public PolicyMode Mode { get; set; } = PolicyMode.Enforce;
    public List<PolicyRule> Rules { get; set; } = new();
}

public sealed class PolicyRule
{
    public string Id { get; set; } = "";
    public string? Description { get; set; }
    public bool Enabled { get; set; } = true;
    public RuleMatch Match { get; set; } = new();
    public Verdict Verdict { get; set; } = Verdict.Log;
    /// <summary>Verdict used instead of <see cref="Verdict"/> when the policy runs in strict mode.</summary>
    public Verdict? VerdictStrict { get; set; }
    public Severity Severity { get; set; } = Severity.Info;
    public bool Alert { get; set; }
    public int TimeoutSeconds { get; set; } = 60;
    public Verdict OnTimeout { get; set; } = Verdict.Block;
    /// <summary>1-based line in the YAML source where the rule starts.</summary>
    public int Line { get; set; }
}

public sealed class RuleMatch
{
    public List<string> Agent { get; set; } = new();
    public List<string> Action { get; set; } = new();
    public List<string> Path { get; set; } = new();
    public List<string> PathNot { get; set; } = new();
    public bool? OutsideCwd { get; set; }
    public Regex? CommandRegex { get; set; }
    public string? CommandRegexSource { get; set; }
    public List<string> Host { get; set; } = new();
    public List<string>? HostNotIn { get; set; }
    public bool? FirstContact { get; set; }
    public List<string> Tool { get; set; } = new();
    public List<string> Target { get; set; } = new();
}

public sealed record PolicyError(int? Line, int? Column, string Message);
