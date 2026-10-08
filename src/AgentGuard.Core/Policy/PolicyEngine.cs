namespace AgentGuard.Core.Policy;

public sealed record PolicyInput(
    string AgentId,
    string Action,
    string Target,
    IReadOnlyDictionary<string, object?>? Details = null,
    string? UserProfile = null,
    string? Cwd = null,
    string AgentTrust = "unknown",
    bool KillSwitchEngaged = false);

public sealed record PolicyDecision(
    // What the matching rule says (after strict-mode substitution).
    Verdict RuleVerdict,
    // What should actually happen after mode, trust and kill switch are applied.
    Verdict Effective,
    string? RuleId,
    Severity Severity,
    bool Alert,
    string Reason,
    int TimeoutSeconds,
    Verdict OnTimeout);

public interface IPolicyContext
{
    /// <summary>True when <paramref name="agentId"/> has never been seen contacting <paramref name="host"/>.</summary>
    bool IsFirstContact(string agentId, string host);
}

/// <summary>Evaluates events against an ordered rule list. First matching rule wins; unmatched events are logged.</summary>
public sealed class PolicyEngine
{
    public const string KillSwitchRuleId = "killswitch";
    public const string TrustBlockedRuleId = "agent-trust-blocked";

    public PolicyDocument Document { get; }

    public PolicyEngine(PolicyDocument document) => Document = document;

    public PolicyDecision Evaluate(PolicyInput input, IPolicyContext? context = null)
    {
        if (input.KillSwitchEngaged)
            return new PolicyDecision(Verdict.Block, Verdict.Block, KillSwitchRuleId, Severity.High, false,
                "Kill switch is engaged; all agent actions are blocked.", 0, Verdict.Block);

        if (string.Equals(input.AgentTrust, "blocked", StringComparison.OrdinalIgnoreCase))
            return new PolicyDecision(Verdict.Block, Verdict.Block, TrustBlockedRuleId, Severity.High, true,
                $"Agent '{input.AgentId}' is marked as blocked.", 0, Verdict.Block);

        var ctx = new PathContext(input.UserProfile, input.Cwd);
        foreach (var rule in Document.Rules)
        {
            if (!rule.Enabled || !Matches(rule.Match, input, ctx, context)) continue;

            var ruleVerdict = Document.Mode == PolicyMode.Strict && rule.VerdictStrict is { } strict ? strict : rule.Verdict;
            var alert = rule.Alert || ruleVerdict is Verdict.Ask or Verdict.Block || rule.Severity >= Severity.High;
            var effective = ApplyModeAndTrust(ruleVerdict, input.AgentTrust);
            var reason = rule.Description ?? $"Matched rule '{rule.Id}'.";
            return new PolicyDecision(ruleVerdict, effective, rule.Id, rule.Severity, alert, reason, rule.TimeoutSeconds, rule.OnTimeout);
        }

        return new PolicyDecision(Verdict.Log, Verdict.Log, null, Severity.Info, false, "No rule matched; logged.", 0, Verdict.Block);
    }

    private Verdict ApplyModeAndTrust(Verdict verdict, string trust)
    {
        if (Document.Mode == PolicyMode.Monitor && verdict is Verdict.Ask or Verdict.Block) return Verdict.Log;
        if (verdict == Verdict.Ask && string.Equals(trust, "allowed", StringComparison.OrdinalIgnoreCase)) return Verdict.Allow;
        return verdict;
    }

    internal static bool Matches(RuleMatch m, PolicyInput input, PathContext ctx, IPolicyContext? context)
    {
        if (m.Agent.Count > 0 && !m.Agent.Any(p => Glob.IsMatch(p, input.AgentId))) return false;
        if (m.Action.Count > 0 && !m.Action.Any(p => Glob.IsMatch(p, input.Action))) return false;
        if (m.Target.Count > 0 && !m.Target.Any(p => Glob.IsMatch(p, input.Target))) return false;

        if (m.Path.Count > 0 || m.PathNot.Count > 0 || m.OutsideCwd is not null)
        {
            var path = Glob.NormalizePath(input.Target);
            if (path.Length == 0) return false;
            if (m.Path.Count > 0 && !m.Path.Any(p => PathMatches(p, path, ctx))) return false;
            if (m.PathNot.Any(p => PathMatches(p, path, ctx))) return false;
            if (m.OutsideCwd is { } outside)
            {
                if (string.IsNullOrEmpty(input.Cwd)) { if (!outside) return false; }
                else if (Glob.IsUnder(path, input.Cwd) == outside) return false;
            }
        }

        if (m.CommandRegex is not null)
        {
            try { if (!m.CommandRegex.IsMatch(input.Target)) return false; }
            catch (System.Text.RegularExpressions.RegexMatchTimeoutException) { return false; }
        }

        if (m.Tool.Count > 0)
        {
            var tool = ToolName(input);
            if (tool is null || !m.Tool.Any(p => Glob.IsMatch(p, tool))) return false;
        }

        if (m.Host.Count > 0 || m.HostNotIn is not null || m.FirstContact is not null)
        {
            var host = HostOf(input);
            if (string.IsNullOrEmpty(host)) return false;
            if (m.Host.Count > 0 && !m.Host.Any(p => Glob.IsMatch(p, host))) return false;
            if (m.HostNotIn is not null && m.HostNotIn.Any(p => Glob.IsMatch(p, host))) return false;
            if (m.FirstContact is { } fc)
            {
                var first = context?.IsFirstContact(input.AgentId, host) ?? false;
                if (first != fc) return false;
            }
        }
        return true;
    }

    private static bool PathMatches(string pattern, string path, PathContext ctx)
    {
        var expanded = Glob.ExpandPattern(pattern, ctx);
        // A pattern with no separator matches the file name only (e.g. "*.pem").
        if (!expanded.Contains('/'))
        {
            var name = path[(path.LastIndexOf('/') + 1)..];
            return Glob.IsMatch(expanded, name, pathMode: true);
        }
        return Glob.IsMatch(expanded, path, pathMode: true);
    }

    private static string? ToolName(PolicyInput input)
    {
        if (input.Details is not null && input.Details.TryGetValue("tool", out var t) && t is string s) return s;
        var slash = input.Target.IndexOf('/');
        return slash >= 0 ? input.Target[(slash + 1)..] : input.Target;
    }

    /// <summary>Extracts a host name from a net.connect target ("host:port", URL, or bare host), preferring a resolved name in details.</summary>
    public static string? HostOf(PolicyInput input)
    {
        if (input.Details is not null && input.Details.TryGetValue("hostname", out var h) && h is string hs && hs.Length > 0)
            return hs.ToLowerInvariant();
        return HostOf(input.Target);
    }

    public static string? HostOf(string target)
    {
        var t = target.Trim();
        if (t.Length == 0) return null;
        if (Uri.TryCreate(t, UriKind.Absolute, out var uri) && uri.Host.Length > 0 && t.Contains("://"))
            return uri.Host.ToLowerInvariant();
        if (t.StartsWith('['))
        {
            var end = t.IndexOf(']');
            return end > 0 ? t[1..end].ToLowerInvariant() : t.ToLowerInvariant();
        }
        var colon = t.LastIndexOf(':');
        if (colon > 0 && t.IndexOf(':') == colon && int.TryParse(t[(colon + 1)..], out _)) t = t[..colon];
        return t.ToLowerInvariant();
    }
}
