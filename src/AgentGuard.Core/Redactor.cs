using System.Text.RegularExpressions;

namespace AgentGuard.Core;

/// <summary>Removes secrets from command lines and tool arguments before they are stored or exported.</summary>
public sealed class Redactor
{
    public const string Replacement = "[REDACTED]";
    private const int MaxStringLength = 4096;
    private readonly List<Regex> _patterns;

    public Redactor(IEnumerable<string> patterns)
    {
        _patterns = new List<Regex>();
        foreach (var p in patterns)
        {
            try { _patterns.Add(new Regex(p, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))); }
            catch (ArgumentException) { /* invalid patterns are rejected by settings validation */ }
        }
    }

    public string Redact(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        var s = value;
        foreach (var r in _patterns)
        {
            try { s = r.Replace(s, Replacement); }
            catch (RegexMatchTimeoutException) { }
        }
        return s.Length > MaxStringLength ? s[..MaxStringLength] + "…" : s;
    }

    public Dictionary<string, object?> Redact(Dictionary<string, object?> details)
    {
        var result = new Dictionary<string, object?>();
        foreach (var (k, v) in details) result[k] = RedactValue(k, v);
        return result;
    }

    private object? RedactValue(string key, object? v)
    {
        if (IsSecretKey(key) && v is string) return Replacement;
        return v switch
        {
            string s => Redact(s),
            Dictionary<string, object?> d => Redact(d),
            IList<object?> list => list.Select(x => RedactValue("", x)).ToList(),
            _ => v,
        };
    }

    private static bool IsSecretKey(string key) =>
        Regex.IsMatch(key, "(?i)^(password|passwd|secret|token|api[_-]?key|authorization|access[_-]?key|private[_-]?key|client[_-]?secret)$");
}
