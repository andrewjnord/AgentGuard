using System.Globalization;
using System.Text.Json;
using AgentGuard.Core;
using AgentGuard.Core.Integration;
using AgentGuard.Core.Policy;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Storage;

namespace AgentGuard.Cli;

/// <summary>Exit codes, documented in the help text so scripts can rely on them.</summary>
public static class ExitCodes
{
    public const int Ok = 0;
    public const int Failed = 1;
    public const int Usage = 2;
    public const int Unreachable = 3;
    public const int IntegrityFailed = 4;
}

/// <summary>The <c>agentguard</c> admin command line: status, policy validation, export and integrity checks.</summary>
public sealed class AdminCli
{
    public const string Help = """
        AgentGuard admin CLI

        Usage:
          agentguard status [--json]
          agentguard policy validate <file> [--base-dir DIR] [--server]
          agentguard policy show [--version N]
          agentguard policy apply <file>
          agentguard mode <monitor|enforce|strict>
          agentguard killswitch <engage|release|terminate>
          agentguard export [--format ocsf|cef|json] [--from TIME] [--to TIME] [--agent ID] [--output FILE]
          agentguard verify [--offline] [--db PATH]
          agentguard version
          agentguard cleanup-integrations [--profiles DIR;DIR] [--keep-hook]
                            Restores MCP client configs and removes the Claude Code hook (run by the uninstaller)

        Connection options (management commands need the admin token, readable by Administrators only):
          --url URL         Service URL (default: AGENTGUARD_URL or the installed port on 127.0.0.1)
          --token TOKEN     Admin token (default: AGENTGUARD_TOKEN, then <data-dir>/admin.token)
          --data-dir DIR    AgentGuard data directory (default: %ProgramData%\AgentGuard)

        Exit codes: 0 ok, 1 failed or invalid, 2 usage error, 3 service unreachable, 4 integrity check failed.
        """;

    private readonly TextWriter _out;
    private readonly TextWriter _err;
    private readonly Func<string, string?, AgentGuardClient> _clientFactory;

    public AdminCli(TextWriter stdout, TextWriter stderr, Func<string, string?, AgentGuardClient>? clientFactory = null)
    {
        _out = stdout;
        _err = stderr;
        _clientFactory = clientFactory ?? ((url, token) => new AgentGuardClient(url, token, TimeSpan.FromSeconds(60), actor: "cli"));
    }

    public async Task<int> RunAsync(string[] argv, CancellationToken ct = default)
    {
        Args a;
        try { a = Args.Parse(argv); }
        catch (ArgumentException ex) { return Usage(ex.Message); }

        try
        {
            return (a.Positional.ElementAtOrDefault(0), a.Positional.ElementAtOrDefault(1)) switch
            {
                ("status", _) => await StatusAsync(a, ct),
                ("policy", "validate") => await ValidateAsync(a, ct),
                ("policy", "show") => await ShowPolicyAsync(a, ct),
                ("policy", "apply") => await ApplyPolicyAsync(a, ct),
                ("mode", { } m) => await SetModeAsync(a, m, ct),
                ("killswitch", { } k) => await KillSwitchAsync(a, k, ct),
                ("export", _) => await ExportAsync(a, ct),
                ("verify", _) => await VerifyAsync(a, ct),
                ("version", _) => Version(),
                ("cleanup-integrations", _) => await CleanupAsync(a),
                ("help", _) or (null, _) => HelpText(),
                _ => Usage($"Unknown command: {string.Join(' ', a.Positional)}"),
            };
        }
        catch (HttpRequestException ex)
        {
            await _err.WriteLineAsync($"The AgentGuard service is not reachable at {ServiceUrl(a)} ({ex.Message}). Is the AgentGuard service running?");
            return ExitCodes.Unreachable;
        }
        catch (AgentGuardApiException ex) when (ex.StatusCode == 401)
        {
            await _err.WriteLineAsync("The service rejected the admin token. Run from an elevated prompt, or pass --token.");
            return ExitCodes.Failed;
        }
        catch (AgentGuardApiException ex)
        {
            await _err.WriteLineAsync(ErrorMessage(ex));
            return ExitCodes.Failed;
        }
        catch (CliException ex)
        {
            await _err.WriteLineAsync(ex.Message);
            return ex.ExitCode;
        }
    }

    // ------------------------------------------------------------------ commands

    private async Task<int> StatusAsync(Args a, CancellationToken ct)
    {
        using var api = Client(a);
        var s = await api.GetAsync<JsonElement>("api/v1/status", ct);
        if (a.Has("json"))
        {
            await _out.WriteLineAsync(JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }));
            return ExitCodes.Ok;
        }
        var c = s.GetProperty("counts");
        var ks = s.GetProperty("killSwitch");
        var integ = s.GetProperty("integrity");
        var caps = s.GetProperty("capabilities");
        string Cap(string k) => caps.GetProperty(k).GetBoolean() ? "yes" : "no";
        await _out.WriteLineAsync($"AgentGuard {s.GetProperty("version").GetString()} on {s.GetProperty("platform").GetString()}{(s.GetProperty("devMode").GetBoolean() ? " (dev/demo mode)" : "")}");
        await _out.WriteLineAsync($"Mode:            {s.GetProperty("mode").GetString()}");
        await _out.WriteLineAsync($"Kill switch:     {(ks.GetProperty("engaged").GetBoolean() ? $"ENGAGED since {ks.GetProperty("since").GetString()} ({ks.GetProperty("suspendedPids").GetInt32()} processes suspended)" : "off")}");
        await _out.WriteLineAsync($"Agents:          {c.GetProperty("agents").GetInt32()} known, {c.GetProperty("activeAgents").GetInt32()} running");
        await _out.WriteLineAsync($"MCP servers:     {c.GetProperty("mcpServers").GetInt32()} found, {c.GetProperty("proxiedMcpServers").GetInt32()} proxied");
        await _out.WriteLineAsync($"Today:           {c.GetProperty("eventsToday").GetInt32()} events, {c.GetProperty("blockedToday").GetInt32()} blocked, {c.GetProperty("askedToday").GetInt32()} asked");
        await _out.WriteLineAsync($"Needs attention: {c.GetProperty("openAlerts").GetInt32()} open alerts, {c.GetProperty("pendingApprovals").GetInt32()} pending approvals");
        var ok = integ.GetProperty("ok");
        await _out.WriteLineAsync($"Audit log:       {(ok.ValueKind == JsonValueKind.Null ? "not verified yet (run 'agentguard verify')" : ok.GetBoolean() ? $"verified {integ.GetProperty("lastVerifiedAt").GetString()}" : "INTEGRITY CHECK FAILED")}");
        await _out.WriteLineAsync($"Enforcement:     hooks {Cap("hooks")}, MCP proxy {Cap("mcpProxy")}, telemetry {Cap("etw")}, process control {Cap("processControl")}, firewall {Cap("firewall")}");
        await _out.WriteLineAsync($"Uptime:          {TimeSpan.FromSeconds(s.GetProperty("uptimeSeconds").GetInt64()):d\\.hh\\:mm\\:ss}");
        return ExitCodes.Ok;
    }

    private async Task<int> ValidateAsync(Args a, CancellationToken ct)
    {
        var file = a.Positional.ElementAtOrDefault(2) ?? throw new CliException("policy validate needs a file.", ExitCodes.Usage);
        var yaml = ReadFile(file);
        List<(int? Line, int? Column, string Message)> errors;
        int rules;
        if (a.Has("server"))
        {
            using var api = Client(a);
            var v = await api.SendAsync(HttpMethod.Post, "api/v1/policy/validate", new { yaml }, ct);
            rules = v.GetProperty("ruleCount").GetInt32();
            errors = v.GetProperty("errors").EnumerateArray().Select(e => (
                e.GetProperty("line").ValueKind == JsonValueKind.Number ? e.GetProperty("line").GetInt32() : (int?)null,
                e.GetProperty("column").ValueKind == JsonValueKind.Number ? e.GetProperty("column").GetInt32() : (int?)null,
                e.GetProperty("message").GetString() ?? "")).ToList();
        }
        else
        {
            var baseDir = a.Value("base-dir") ?? Path.GetDirectoryName(Path.GetFullPath(file));
            var r = PolicyParser.Parse(yaml, baseDir);
            rules = r.Document?.Rules.Count ?? 0;
            errors = r.Errors.Select(e => (e.Line, e.Column, e.Message)).ToList();
        }
        if (errors.Count == 0)
        {
            await _out.WriteLineAsync($"{file}: valid ({rules} rule{(rules == 1 ? "" : "s")}).");
            return ExitCodes.Ok;
        }
        foreach (var e in errors)
            await _err.WriteLineAsync($"{file}:{e.Line?.ToString() ?? "?"}:{e.Column?.ToString() ?? "?"}: error: {e.Message}");
        await _err.WriteLineAsync($"{file}: {errors.Count} error{(errors.Count == 1 ? "" : "s")}.");
        return ExitCodes.Failed;
    }

    private async Task<int> ShowPolicyAsync(Args a, CancellationToken ct)
    {
        using var api = Client(a);
        var path = a.Value("version") is { } v ? $"api/v1/policy/history/{int.Parse(v, CultureInfo.InvariantCulture)}" : "api/v1/policy";
        var p = await api.GetAsync<JsonElement>(path, ct);
        await _err.WriteLineAsync($"# policy v{p.GetProperty("version").GetInt32()}, applied {p.GetProperty("appliedAt").GetString()} by {p.GetProperty("appliedBy").GetString()}, mode {p.GetProperty("mode").GetString()}, {p.GetProperty("ruleCount").GetInt32()} rules");
        await _out.WriteAsync(p.GetProperty("yaml").GetString());
        return ExitCodes.Ok;
    }

    private async Task<int> ApplyPolicyAsync(Args a, CancellationToken ct)
    {
        var file = a.Positional.ElementAtOrDefault(2) ?? throw new CliException("policy apply needs a file.", ExitCodes.Usage);
        using var api = Client(a);
        try
        {
            var p = await api.SendAsync(HttpMethod.Put, "api/v1/policy", new { yaml = ReadFile(file) }, ct);
            await _out.WriteLineAsync($"Applied policy v{p.GetProperty("version").GetInt32()} ({p.GetProperty("ruleCount").GetInt32()} rules, mode {p.GetProperty("mode").GetString()}).");
            return ExitCodes.Ok;
        }
        catch (AgentGuardApiException ex) when (ex.StatusCode == 400)
        {
            using var doc = JsonDocument.Parse(ex.Body);
            foreach (var e in doc.RootElement.GetProperty("errors").EnumerateArray())
                await _err.WriteLineAsync($"{file}:{Num(e, "line")}:{Num(e, "column")}: error: {e.GetProperty("message").GetString()}");
            await _err.WriteLineAsync("The policy was not applied.");
            return ExitCodes.Failed;
        }
    }

    private async Task<int> SetModeAsync(Args a, string mode, CancellationToken ct)
    {
        if (mode is not ("monitor" or "enforce" or "strict")) return Usage("mode must be monitor, enforce or strict.");
        using var api = Client(a);
        var s = await api.SendAsync(HttpMethod.Put, "api/v1/mode", new { mode }, ct);
        await _out.WriteLineAsync($"Mode is now {s.GetProperty("mode").GetString()}.");
        return ExitCodes.Ok;
    }

    private async Task<int> KillSwitchAsync(Args a, string action, CancellationToken ct)
    {
        if (action is not ("engage" or "release" or "terminate")) return Usage("killswitch takes engage, release or terminate.");
        using var api = Client(a);
        var s = await api.SendAsync(HttpMethod.Post, "api/v1/killswitch", new { action }, ct);
        var ks = s.GetProperty("killSwitch");
        await _out.WriteLineAsync(ks.GetProperty("engaged").GetBoolean()
            ? $"Kill switch engaged ({ks.GetProperty("suspendedPids").GetInt32()} processes suspended)."
            : "Kill switch released.");
        return ExitCodes.Ok;
    }

    private async Task<int> ExportAsync(Args a, CancellationToken ct)
    {
        var format = a.Value("format") ?? "ocsf";
        if (format is not ("ocsf" or "cef" or "json")) return Usage("--format must be ocsf, cef or json.");
        var query = new List<string> { "format=" + format };
        foreach (var (opt, param) in new[] { ("from", "from"), ("to", "to"), ("agent", "agentId") })
        {
            if (a.Value(opt) is not { } v) continue;
            if (opt is "from" or "to")
            {
                if (!DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var t))
                    return Usage($"--{opt} is not a date or time: {v}");
                v = t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
            }
            query.Add($"{param}={Uri.EscapeDataString(v)}");
        }
        using var api = Client(a);
        await using var stream = await api.OpenStreamAsync("api/v1/export?" + string.Join('&', query), ct);
        var output = a.Value("output");
        long bytes;
        if (output is null)
        {
            using var reader = new StreamReader(stream);
            var buffer = new char[16 * 1024];
            int n;
            while ((n = await reader.ReadAsync(buffer, ct)) > 0) await _out.WriteAsync(buffer.AsMemory(0, n), ct);
            await _out.FlushAsync(ct);
            return ExitCodes.Ok;
        }
        await using (var file = File.Create(output))
        {
            await stream.CopyToAsync(file, ct);
            bytes = file.Length;
        }
        var lines = File.ReadLines(output).LongCount();
        await _err.WriteLineAsync($"Exported {lines} event{(lines == 1 ? "" : "s")} ({format}, {bytes:N0} bytes) to {output}.");
        return ExitCodes.Ok;
    }

    private async Task<int> VerifyAsync(Args a, CancellationToken ct)
    {
        IntegrityResultView r;
        if (a.Has("offline"))
        {
            var db = a.Value("db") ?? Path.Combine(DataDir(a), "agentguard.db");
            if (!File.Exists(db)) throw new CliException($"Database not found: {db}", ExitCodes.Failed);
            r = VerifyCopy(db);
            await _out.WriteLineAsync($"Checked a copy of {db} (the original is not modified).");
        }
        else
        {
            using var api = Client(a);
            var v = await api.SendAsync(HttpMethod.Post, "api/v1/integrity/verify", null, ct);
            r = new IntegrityResultView(v.GetProperty("ok").GetBoolean(), v.GetProperty("checked").GetInt64(),
                v.GetProperty("firstBadId").ValueKind == JsonValueKind.Number ? v.GetProperty("firstBadId").GetInt64() : null);
        }
        if (r.Ok)
        {
            await _out.WriteLineAsync($"Audit log intact: {r.Checked:N0} event{(r.Checked == 1 ? "" : "s")} verified.");
            return ExitCodes.Ok;
        }
        await _err.WriteLineAsync($"AUDIT LOG INTEGRITY CHECK FAILED at event {r.FirstBadId} ({r.Checked:N0} checked). Events from that point may have been altered or removed.");
        return ExitCodes.IntegrityFailed;
    }

    /// <summary>
    /// Undoes what AgentGuard changed outside its own folders, so uninstalling never leaves an MCP client pointing at a
    /// deleted proxy: proxied stdio servers are unwrapped, redirected HTTP servers get their original URL back, and the
    /// machine-wide Claude Code hook is removed. Works with the service stopped; reads the database for HTTP upstreams.
    /// </summary>
    private async Task<int> CleanupAsync(Args a)
    {
        var restored = 0;
        var failed = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Try(string what, Action act)
        {
            try { act(); restored++; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
            {
                failed++;
                _err.WriteLine($"Could not restore {what}: {ex.Message}");
            }
        }

        var db = Path.Combine(DataDir(a), "agentguard.db");
        if (File.Exists(db))
        {
            using var store = new EventStore(db);
            foreach (var s in store.ListMcpServers(includeMissing: true).Where(s => s.Proxied && File.Exists(s.ConfigPath)))
            {
                seen.Add(s.ConfigPath + "|" + string.Join('/', s.JsonPath));
                if (s.Transport == "stdio") Try($"{s.Name} in {s.ConfigPath}", () => McpConfigRewriter.UnwrapStdio(s.ConfigPath, s.JsonPath));
                else if (!string.IsNullOrEmpty(s.UpstreamUrl)) Try($"{s.Name} in {s.ConfigPath}", () => McpConfigRewriter.SetUrl(s.ConfigPath, s.JsonPath, s.UpstreamUrl!));
            }
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        }

        // Anything still wrapped that the database does not know about (copied configs, a reset database).
        var signatures = Path.Combine(AppContext.BaseDirectory, "defaults", "signatures", "agents.yaml");
        if (File.Exists(signatures))
        {
            var clients = Core.Discovery.SignatureFile.Load(signatures).McpClients;
            foreach (var s in Core.Discovery.McpConfigScanner.Scan(clients, Profiles(a)))
            {
                if (s.Transport != "stdio" || !s.Proxied || !seen.Add(s.ConfigPath + "|" + string.Join('/', s.JsonPath))) continue;
                Try($"{s.Name} in {s.ConfigPath}", () => McpConfigRewriter.UnwrapStdio(s.ConfigPath, s.JsonPath));
            }
        }

        if (!a.Has("keep-hook"))
        {
            var hook = ClaudeSettings.ManagedDropInPath();
            if (ClaudeSettings.IsInstalled(hook)) Try("the Claude Code hook", () => ClaudeSettings.Uninstall(hook));
        }

        await _out.WriteLineAsync($"Restored {restored} integration{(restored == 1 ? "" : "s")}{(failed > 0 ? $", {failed} failed" : "")}.");
        return failed > 0 ? ExitCodes.Failed : ExitCodes.Ok;
    }

    private static IEnumerable<string> Profiles(Args a)
    {
        if (a.Value("profiles") is { } list) return list.Split(';', StringSplitOptions.RemoveEmptyEntries);
        var root = OperatingSystem.IsWindows()
            ? Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users"
            : "/home";
        var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Public", "Default", "Default User", "All Users", "WDAGUtilityAccount" };
        return Directory.Exists(root) ? Directory.GetDirectories(root).Where(d => !skip.Contains(Path.GetFileName(d))) : Array.Empty<string>();
    }

    private sealed record IntegrityResultView(bool Ok, long Checked, long? FirstBadId);

    /// <summary>Verifies a private copy (database plus WAL) so evidence is never touched, even by SQLite housekeeping.</summary>
    private static IntegrityResultView VerifyCopy(string db)
    {
        var dir = Path.Combine(Path.GetTempPath(), "agentguard-verify-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        try
        {
            var copy = Path.Combine(dir, "agentguard.db");
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                if (!File.Exists(db + suffix)) continue;
                using var src = new FileStream(db + suffix, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var dst = File.Create(copy + suffix);
                src.CopyTo(dst);
            }
            using var store = new EventStore(copy);
            var r = store.VerifyIntegrity();
            return new IntegrityResultView(r.Ok, r.Checked, r.FirstBadId);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    private int Version()
    {
        var v = typeof(AdminCli).Assembly.GetName().Version;
        _out.WriteLine($"agentguard {v?.ToString(3)}");
        return ExitCodes.Ok;
    }

    private int HelpText()
    {
        _out.WriteLine(Help);
        return ExitCodes.Ok;
    }

    private int Usage(string message)
    {
        _err.WriteLine(message);
        _err.WriteLine("Run 'agentguard help' for usage.");
        return ExitCodes.Usage;
    }

    // ------------------------------------------------------------------ helpers

    private static string ServiceUrl(Args a) =>
        a.Value("url") is { } u ? u.TrimEnd('/') + "/" : ClientConfig.Load(Path.Combine(DataDir(a), "public", "client.json")).ResolveBaseUrl();

    private static string DataDir(Args a) =>
        a.Value("data-dir") ?? Environment.GetEnvironmentVariable("AGENTGUARD_DATA_DIR") ?? (OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AgentGuard")
            : Path.Combine(Directory.GetCurrentDirectory(), "data"));

    private AgentGuardClient Client(Args a) => _clientFactory(ServiceUrl(a), Token(a));

    private static string Token(Args a)
    {
        if (a.Value("token") is { Length: > 0 } t) return t;
        if (Environment.GetEnvironmentVariable("AGENTGUARD_TOKEN") is { Length: > 0 } e) return e;
        var path = Path.Combine(DataDir(a), "admin.token");
        try { return File.ReadAllText(path).Trim(); }
        catch (UnauthorizedAccessException) { throw new CliException($"Access to {path} was denied. Run this command from an elevated (Administrator) prompt, or pass --token.", ExitCodes.Failed); }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new CliException($"No admin token at {path}. Is AgentGuard installed and its service running? (Or pass --token / --data-dir.)", ExitCodes.Failed);
        }
    }

    private static string ReadFile(string path)
    {
        try { return File.ReadAllText(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { throw new CliException($"Cannot read {path}: {ex.Message}", ExitCodes.Failed); }
    }

    private static string ErrorMessage(AgentGuardApiException ex)
    {
        try
        {
            using var doc = JsonDocument.Parse(ex.Body);
            if (doc.RootElement.TryGetProperty("error", out var e)) return $"AgentGuard: {e.GetString()} (HTTP {ex.StatusCode})";
        }
        catch (JsonException) { }
        return ex.Message;
    }

    private static string Num(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32().ToString(CultureInfo.InvariantCulture) : "?";
}

public sealed class CliException(string message, int exitCode) : Exception(message)
{
    public int ExitCode { get; } = exitCode;
}

/// <summary>Minimal argument parser: positionals, <c>--flag</c>, <c>--name value</c> and <c>--name=value</c>.</summary>
public sealed class Args
{
    private static readonly HashSet<string> Flags = new() { "json", "server", "offline", "help", "keep-hook" };
    private static readonly HashSet<string> Valued = new() { "url", "token", "data-dir", "base-dir", "format", "from", "to", "agent", "output", "db", "version", "profiles" };

    public List<string> Positional { get; } = new();
    private readonly Dictionary<string, string?> _options = new();

    public static Args Parse(string[] argv)
    {
        var a = new Args();
        for (var i = 0; i < argv.Length; i++)
        {
            var s = argv[i];
            if (s is "-h") s = "--help";
            if (s is "-o") s = "--output";
            if (!s.StartsWith("--", StringComparison.Ordinal)) { a.Positional.Add(s); continue; }
            var name = s[2..];
            string? value = null;
            var eq = name.IndexOf('=');
            if (eq >= 0) { value = name[(eq + 1)..]; name = name[..eq]; }
            if (Flags.Contains(name)) { a._options[name] = "true"; continue; }
            if (!Valued.Contains(name)) throw new ArgumentException($"Unknown option --{name}.");
            if (value is null)
            {
                if (i + 1 >= argv.Length) throw new ArgumentException($"--{name} needs a value.");
                value = argv[++i];
            }
            a._options[name] = value;
        }
        if (a.Has("help")) a.Positional.Insert(0, "help");
        return a;
    }

    public bool Has(string name) => _options.ContainsKey(name);
    public string? Value(string name) => _options.TryGetValue(name, out var v) ? v : null;
}
