using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Policy;

/// <summary>
/// Glob matching for paths, agent ids, tools and hosts.
/// <c>**</c> matches across separators, <c>*</c> matches within one segment, <c>?</c> matches one character.
/// Matching is case-insensitive. Paths are normalised to forward slashes before matching.
/// </summary>
public static class Glob
{
    private static readonly ConcurrentDictionary<(string, bool), Regex> Cache = new();

    public static bool IsMatch(string pattern, string value, bool pathMode = false)
    {
        if (pattern == "*" || pattern == "**") return true;
        var regex = Cache.GetOrAdd((pattern, pathMode), static k => Compile(k.Item1, k.Item2));
        return regex.IsMatch(value);
    }

    private static Regex Compile(string pattern, bool pathMode)
    {
        var sb = new StringBuilder("^");
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '*')
            {
                if (i + 1 < pattern.Length && pattern[i + 1] == '*')
                {
                    i++;
                    // "**/" also matches zero directories.
                    if (i + 1 < pattern.Length && pattern[i + 1] == '/') { i++; sb.Append("(?:.*/)?"); }
                    else sb.Append(".*");
                }
                else sb.Append(pathMode ? "[^/]*" : ".*");
            }
            else if (c == '?') sb.Append(pathMode ? "[^/]" : ".");
            else sb.Append(Regex.Escape(c.ToString()));
        }
        sb.Append('$');
        return new Regex(sb.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    }

    /// <summary>Normalises a Windows or POSIX path for matching: forward slashes, no trailing slash, no duplicate slashes.</summary>
    public static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        var p = path.Trim().Trim('"').Replace('\\', '/');
        if (p.StartsWith("//?/")) p = p[4..];           // \\?\C:\...
        if (p.StartsWith("/??/")) p = p[4..];           // \??\C:\... (NT paths)
        while (p.Contains("//")) p = p.Replace("//", "/");
        if (p.Length > 1 && p.EndsWith('/')) p = p.TrimEnd('/');
        return p;
    }

    /// <summary>Expands ~ and %VARS% in a path pattern for a given user context, then normalises it.</summary>
    public static string ExpandPattern(string pattern, PathContext ctx)
    {
        var p = pattern.Trim();
        var home = NormalizePath(ctx.UserProfile ?? "");
        if (home.Length > 0)
        {
            if (p == "~") p = home;
            else if (p.StartsWith("~/") || p.StartsWith("~\\")) p = home + "/" + p[2..];
            p = ReplaceVar(p, "%USERPROFILE%", home);
            p = ReplaceVar(p, "%APPDATA%", home + "/AppData/Roaming");
            p = ReplaceVar(p, "%LOCALAPPDATA%", home + "/AppData/Local");
        }
        p = ReplaceVar(p, "%PROGRAMDATA%", NormalizePath(ctx.ProgramData));
        p = ReplaceVar(p, "%SYSTEMROOT%", NormalizePath(ctx.SystemRoot));
        return NormalizePath(p);
    }

    private static string ReplaceVar(string s, string var, string value) =>
        s.Replace(var, value, StringComparison.OrdinalIgnoreCase);

    /// <summary>True when <paramref name="path"/> is inside <paramref name="dir"/> (or equal to it).</summary>
    public static bool IsUnder(string path, string dir)
    {
        var p = NormalizePath(path);
        var d = NormalizePath(dir);
        if (d.Length == 0) return false;
        return p.Equals(d, StringComparison.OrdinalIgnoreCase)
               || p.StartsWith(d + "/", StringComparison.OrdinalIgnoreCase);
    }
}

public sealed record PathContext(string? UserProfile, string? Cwd = null)
{
    public string ProgramData { get; init; } =
        Environment.GetEnvironmentVariable("ProgramData") ?? (OperatingSystem.IsWindows() ? @"C:\ProgramData" : "/var/lib");
    public string SystemRoot { get; init; } =
        Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
}
