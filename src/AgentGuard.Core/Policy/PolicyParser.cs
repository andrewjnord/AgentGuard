using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace AgentGuard.Core.Policy;

/// <summary>Parses and validates policy YAML, reporting errors with line numbers.</summary>
public static class PolicyParser
{
    private static readonly HashSet<string> RootKeys = new() { "version", "mode", "rules" };
    private static readonly HashSet<string> RuleKeys = new()
    {
        "id", "description", "enabled", "match", "verdict", "verdict_strict", "severity", "alert", "timeout_seconds", "on_timeout",
    };
    private static readonly HashSet<string> MatchKeys = new()
    {
        "agent", "action", "path", "path_not", "outside_cwd", "command_regex", "host", "host_not_in", "first_contact", "tool", "target",
    };

    public sealed record Result(PolicyDocument? Document, IReadOnlyList<PolicyError> Errors)
    {
        public bool Ok => Errors.Count == 0 && Document is not null;
    }

    /// <param name="yaml">Policy source.</param>
    /// <param name="baseDir">Directory used to resolve relative file references such as <c>host_not_in</c> lists.</param>
    public static Result Parse(string yaml, string? baseDir = null)
    {
        var errors = new List<PolicyError>();
        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(yaml));
        }
        catch (YamlException ex)
        {
            errors.Add(new PolicyError(ToLine(ex.Start), ToCol(ex.Start), "YAML syntax error: " + Clean(ex.Message)));
            return new Result(null, errors);
        }

        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            errors.Add(new PolicyError(1, 1, "Policy must be a YAML mapping with 'version', 'mode' and 'rules'."));
            return new Result(null, errors);
        }

        var doc = new PolicyDocument();
        foreach (var (keyNode, valueNode) in root.Children)
        {
            var key = Scalar(keyNode);
            if (key is null || !RootKeys.Contains(key))
            {
                errors.Add(Err(keyNode, $"Unknown top-level key '{key}'. Allowed: version, mode, rules."));
                continue;
            }
            switch (key)
            {
                case "version":
                    if (!int.TryParse(Scalar(valueNode), out var v) || v != 1)
                        errors.Add(Err(valueNode, "Only 'version: 1' is supported."));
                    break;
                case "mode":
                    if (TryEnum<PolicyMode>(Scalar(valueNode), out var mode)) doc.Mode = mode;
                    else errors.Add(Err(valueNode, "mode must be one of: monitor, enforce, strict."));
                    break;
                case "rules":
                    if (valueNode is YamlSequenceNode seq)
                    {
                        foreach (var item in seq.Children)
                        {
                            var rule = ParseRule(item, baseDir, errors);
                            if (rule is not null) doc.Rules.Add(rule);
                        }
                    }
                    else if (!(valueNode is YamlScalarNode s && string.IsNullOrEmpty(s.Value)))
                    {
                        errors.Add(Err(valueNode, "'rules' must be a list."));
                    }
                    break;
            }
        }

        var dupes = doc.Rules.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1);
        foreach (var g in dupes)
            errors.Add(new PolicyError(g.Skip(1).First().Line, 1, $"Duplicate rule id '{g.Key}'."));

        return new Result(errors.Count == 0 ? doc : null, errors);
    }

    private static PolicyRule? ParseRule(YamlNode node, string? baseDir, List<PolicyError> errors)
    {
        if (node is not YamlMappingNode map)
        {
            errors.Add(Err(node, "Each rule must be a mapping."));
            return null;
        }
        var rule = new PolicyRule { Line = ToLine(node.Start) ?? 0 };
        var startErrors = errors.Count;
        var hasVerdict = false;
        foreach (var (k, v) in map.Children)
        {
            var key = Scalar(k);
            if (key is null || !RuleKeys.Contains(key))
            {
                errors.Add(Err(k, $"Unknown rule key '{key}'."));
                continue;
            }
            switch (key)
            {
                case "id":
                    rule.Id = Scalar(v) ?? "";
                    if (!Regex.IsMatch(rule.Id, "^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"))
                        errors.Add(Err(v, "Rule id must be 1-100 characters: letters, digits, '.', '_' or '-'."));
                    break;
                case "description": rule.Description = Scalar(v); break;
                case "enabled":
                    if (bool.TryParse(Scalar(v), out var en)) rule.Enabled = en;
                    else errors.Add(Err(v, "enabled must be true or false."));
                    break;
                case "verdict":
                    hasVerdict = true;
                    if (TryEnum<Verdict>(Scalar(v), out var verdict)) rule.Verdict = verdict;
                    else errors.Add(Err(v, "verdict must be one of: allow, log, ask, block."));
                    break;
                case "verdict_strict":
                    if (TryEnum<Verdict>(Scalar(v), out var vs)) rule.VerdictStrict = vs;
                    else errors.Add(Err(v, "verdict_strict must be one of: allow, log, ask, block."));
                    break;
                case "on_timeout":
                    if (TryEnum<Verdict>(Scalar(v), out var ot) && ot is Verdict.Allow or Verdict.Block) rule.OnTimeout = ot;
                    else errors.Add(Err(v, "on_timeout must be allow or block."));
                    break;
                case "severity":
                    if (TryEnum<Severity>(Scalar(v), out var sev)) rule.Severity = sev;
                    else errors.Add(Err(v, "severity must be one of: info, low, medium, high, critical."));
                    break;
                case "alert":
                    if (bool.TryParse(Scalar(v), out var al)) rule.Alert = al;
                    else errors.Add(Err(v, "alert must be true or false."));
                    break;
                case "timeout_seconds":
                    if (int.TryParse(Scalar(v), out var t) && t is >= 5 and <= 3600) rule.TimeoutSeconds = t;
                    else errors.Add(Err(v, "timeout_seconds must be a number between 5 and 3600."));
                    break;
                case "match":
                    rule.Match = ParseMatch(v, baseDir, errors);
                    break;
            }
        }
        if (string.IsNullOrEmpty(rule.Id)) errors.Add(Err(node, "Rule is missing 'id'."));
        if (!hasVerdict) errors.Add(Err(node, $"Rule '{rule.Id}' is missing 'verdict'."));
        return errors.Count == startErrors ? rule : null;
    }

    private static RuleMatch ParseMatch(YamlNode node, string? baseDir, List<PolicyError> errors)
    {
        var m = new RuleMatch();
        if (node is not YamlMappingNode map)
        {
            errors.Add(Err(node, "'match' must be a mapping."));
            return m;
        }
        foreach (var (k, v) in map.Children)
        {
            var key = Scalar(k);
            if (key is null || !MatchKeys.Contains(key))
            {
                errors.Add(Err(k, $"Unknown match key '{key}'. Allowed: {string.Join(", ", MatchKeys)}."));
                continue;
            }
            switch (key)
            {
                case "agent": m.Agent = List(v, errors); break;
                case "action": m.Action = List(v, errors); break;
                case "path": m.Path = List(v, errors); break;
                case "path_not": m.PathNot = List(v, errors); break;
                case "host": m.Host = List(v, errors); break;
                case "tool": m.Tool = List(v, errors); break;
                case "target": m.Target = List(v, errors); break;
                case "outside_cwd":
                    if (bool.TryParse(Scalar(v), out var oc)) m.OutsideCwd = oc;
                    else errors.Add(Err(v, "outside_cwd must be true or false."));
                    break;
                case "first_contact":
                    if (bool.TryParse(Scalar(v), out var fc)) m.FirstContact = fc;
                    else errors.Add(Err(v, "first_contact must be true or false."));
                    break;
                case "command_regex":
                    var src = Scalar(v);
                    try
                    {
                        m.CommandRegex = new Regex(src ?? "", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250));
                        m.CommandRegexSource = src;
                    }
                    catch (ArgumentException ex)
                    {
                        errors.Add(Err(v, "Invalid command_regex: " + ex.Message));
                    }
                    break;
                case "host_not_in":
                    m.HostNotIn = v is YamlScalarNode
                        ? LoadList(Scalar(v) ?? "", baseDir, v, errors)
                        : List(v, errors);
                    break;
            }
        }
        return m;
    }

    private static List<string> LoadList(string file, string? baseDir, YamlNode node, List<PolicyError> errors)
    {
        var path = Path.IsPathRooted(file) ? file : Path.Combine(baseDir ?? Directory.GetCurrentDirectory(), file);
        if (!File.Exists(path))
        {
            errors.Add(Err(node, $"host_not_in file not found: {file}"));
            return new List<string>();
        }
        return File.ReadAllLines(path)
            .Select(l => l.Split('#')[0].Trim())
            .Where(l => l.Length > 0)
            .ToList();
    }

    private static List<string> List(YamlNode node, List<PolicyError> errors)
    {
        switch (node)
        {
            case YamlScalarNode s:
                return string.IsNullOrEmpty(s.Value) ? new List<string>() : new List<string> { s.Value };
            case YamlSequenceNode seq:
                var list = new List<string>();
                foreach (var item in seq.Children)
                {
                    if (item is YamlScalarNode si && si.Value is not null) list.Add(si.Value);
                    else errors.Add(Err(item, "List items must be plain strings."));
                }
                return list;
            default:
                errors.Add(Err(node, "Expected a string or a list of strings."));
                return new List<string>();
        }
    }

    private static string? Scalar(YamlNode node) => (node as YamlScalarNode)?.Value;

    private static bool TryEnum<T>(string? s, out T value) where T : struct, Enum =>
        Enum.TryParse(s, ignoreCase: true, out value) && Enum.IsDefined(value) && !int.TryParse(s, out _);

    private static PolicyError Err(YamlNode node, string message) => new(ToLine(node.Start), ToCol(node.Start), message);
    private static int? ToLine(Mark m) => m.Line > 0 ? (int)m.Line : null;
    private static int? ToCol(Mark m) => m.Column > 0 ? (int)m.Column : null;

    private static string Clean(string message)
    {
        var i = message.IndexOf("): ", StringComparison.Ordinal);
        return i >= 0 ? message[(i + 3)..] : message;
    }
}
