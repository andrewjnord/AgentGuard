using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Policy;

/// <summary>Small edits to policy YAML that keep the author's comments and layout intact.</summary>
public static class PolicyText
{
    private static readonly Regex ModeLine = new(@"^mode\s*:.*$", RegexOptions.Multiline);
    private static readonly Regex RulesLine = new(@"^rules\s*:\s*(\[\s*\])?\s*$", RegexOptions.Multiline);

    public static string SetMode(string yaml, PolicyMode mode)
    {
        var line = "mode: " + mode.ToString().ToLowerInvariant();
        if (ModeLine.IsMatch(yaml)) return ModeLine.Replace(yaml, line, 1);
        var v = Regex.Match(yaml, @"^version\s*:.*$", RegexOptions.Multiline);
        return v.Success ? yaml.Insert(v.Index + v.Length, "\n" + line) : line + "\n" + yaml;
    }

    /// <summary>Inserts an "always allow" rule as the first rule so it wins over broader asks.</summary>
    public static (string Yaml, string RuleId) AddAllowRule(string yaml, string agentId, string action, string target, string decidedBy)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{agentId}|{action}|{target}")))[..10].ToLowerInvariant();
        var id = "user-allow-" + hash;
        if (yaml.Contains("id: " + id)) return (yaml, id);

        var m = RulesLine.Match(yaml);
        var rest = m.Success ? yaml[(m.Index + m.Length)..] : "";
        // Reuse the indentation of the existing list items so the sequence stays valid YAML.
        var firstItem = Regex.Match(rest, @"^( *)- ", RegexOptions.Multiline);
        var indent = firstItem.Success ? firstItem.Groups[1].Value : "  ";
        var inner = indent + "  ";

        var targetKey = action.StartsWith("file.", StringComparison.Ordinal) ? "path" : "target";
        var sb = new StringBuilder();
        sb.Append(indent).Append("- id: ").Append(id).Append('\n');
        sb.Append(inner).Append("description: ").Append(Quote($"Always allowed by {decidedBy} on {DateTimeOffset.UtcNow:yyyy-MM-dd}")).Append('\n');
        sb.Append(inner).Append("match:\n");
        sb.Append(inner).Append("  agent: ").Append(Quote(agentId)).Append('\n');
        sb.Append(inner).Append("  action: ").Append(Quote(action)).Append('\n');
        sb.Append(inner).Append("  ").Append(targetKey).Append(": ").Append(Quote(EscapeGlob(target))).Append('\n');
        sb.Append(inner).Append("verdict: allow\n");

        if (!m.Success)
            return (yaml.TrimEnd() + "\nrules:\n" + sb, id);
        return (yaml[..m.Index] + "rules:\n" + sb + rest.TrimStart('\r', '\n'), id);
    }

    private static string EscapeGlob(string s) => s.Replace("*", "?").Replace("\n", " ");

    public static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
}
