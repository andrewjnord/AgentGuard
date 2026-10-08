using AgentGuard.Core;
using AgentGuard.Core.Policy;
using Xunit;

namespace AgentGuard.Core.Tests;

public static class Repo
{
    public static string Root
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "AgentGuard.sln"))) dir = dir.Parent;
            return dir?.FullName ?? throw new InvalidOperationException("Repo root not found");
        }
    }

    public static string PoliciesDir => Path.Combine(Root, "policies");
    public static string DefaultPolicy => File.ReadAllText(Path.Combine(PoliciesDir, "default.yaml"));

    public static PolicyEngine DefaultEngine(PolicyMode? mode = null)
    {
        var r = PolicyParser.Parse(DefaultPolicy, PoliciesDir);
        Assert.True(r.Ok, string.Join("\n", r.Errors.Select(e => $"{e.Line}: {e.Message}")));
        if (mode is not null) r.Document!.Mode = mode.Value;
        return new PolicyEngine(r.Document!);
    }
}

public class PolicyParserTests
{
    [Fact]
    public void DefaultPolicyParses()
    {
        var engine = Repo.DefaultEngine();
        Assert.Equal(PolicyMode.Enforce, engine.Document.Mode);
        Assert.True(engine.Document.Rules.Count >= 10);
        Assert.Contains(engine.Document.Rules, r => r.Id == "protect-ssh-keys");
    }

    [Fact]
    public void ReportsYamlSyntaxErrorWithLine()
    {
        var r = PolicyParser.Parse("version: 1\nmode: enforce\nrules:\n  - id: x\n    verdict: [block\n");
        Assert.False(r.Ok);
        Assert.NotNull(r.Errors[0].Line);
    }

    [Fact]
    public void ReportsUnknownKeysAndBadValues()
    {
        var yaml = """
            version: 1
            mode: sometimes
            rules:
              - id: a
                verdict: maybe
                match:
                  colour: red
              - verdict: block
            """;
        var r = PolicyParser.Parse(yaml);
        Assert.False(r.Ok);
        Assert.Contains(r.Errors, e => e.Message.Contains("mode must be") && e.Line == 2);
        Assert.Contains(r.Errors, e => e.Message.Contains("verdict must be") && e.Line == 5);
        Assert.Contains(r.Errors, e => e.Message.Contains("Unknown match key 'colour'"));
        Assert.Contains(r.Errors, e => e.Message.Contains("missing 'id'"));
    }

    [Fact]
    public void RejectsDuplicateIdsAndBadRegex()
    {
        var yaml = """
            version: 1
            rules:
              - id: a
                verdict: log
              - id: a
                verdict: log
              - id: b
                verdict: log
                match:
                  command_regex: "(unclosed"
            """;
        var r = PolicyParser.Parse(yaml);
        Assert.Contains(r.Errors, e => e.Message.Contains("Duplicate rule id"));
        Assert.Contains(r.Errors, e => e.Message.Contains("Invalid command_regex"));
    }

    [Fact]
    public void MissingHostFileIsAnError()
    {
        var yaml = "version: 1\nrules:\n  - id: a\n    verdict: log\n    match:\n      host_not_in: nope.txt\n";
        var r = PolicyParser.Parse(yaml, Path.GetTempPath());
        Assert.Contains(r.Errors, e => e.Message.Contains("not found"));
    }
}

public class PolicyEngineTests
{
    private const string Home = @"C:\Users\ana";

    private static PolicyDecision Eval(PolicyEngine e, string action, string target, string agent = "claude-code", string? cwd = @"C:\Users\ana\src\app",
        string trust = "unknown", bool kill = false, IPolicyContext? ctx = null, Dictionary<string, object?>? details = null) =>
        e.Evaluate(new PolicyInput(agent, action, target, details, Home, cwd, trust, kill), ctx);

    [Theory]
    [InlineData(@"C:\Users\ana\.ssh\id_ed25519")]
    [InlineData(@"C:/Users/ana/.ssh/config")]
    [InlineData(@"C:\Users\ana\.aws\credentials")]
    [InlineData(@"c:\users\ANA\.ssh\known_hosts")]
    public void BlocksSecretReads(string path)
    {
        var d = Eval(Repo.DefaultEngine(), Actions.FileRead, path);
        Assert.Equal(Verdict.Block, d.Effective);
        Assert.Equal("protect-ssh-keys", d.RuleId);
        Assert.True(d.Alert);
    }

    [Fact]
    public void AllowsOrdinaryReads()
    {
        var d = Eval(Repo.DefaultEngine(), Actions.FileRead, @"C:\Users\ana\src\app\README.md");
        Assert.Equal(Verdict.Log, d.Effective);
        Assert.Null(d.RuleId);
    }

    [Fact]
    public void BlocksBrowserProfiles()
    {
        var d = Eval(Repo.DefaultEngine(), Actions.FileRead, @"C:\Users\ana\AppData\Local\Google\Chrome\User Data\Default\Cookies");
        Assert.Equal("protect-browser-data", d.RuleId);
        Assert.Equal(Verdict.Block, d.Effective);
    }

    [Theory]
    [InlineData("rm -rf node_modules")]
    [InlineData("rm -fr /")]
    [InlineData("Remove-Item -Path .\\build -Recurse -Force")]
    [InlineData("del /s /q *.*")]
    [InlineData("rmdir /s /q dist")]
    [InlineData("git push origin main --force")]
    [InlineData("git reset --hard HEAD~3")]
    public void AsksForDestructiveCommands(string command)
    {
        var d = Eval(Repo.DefaultEngine(), Actions.ShellExec, command);
        Assert.Equal("confirm-recursive-delete", d.RuleId);
        Assert.Equal(Verdict.Ask, d.Effective);
        Assert.Equal(60, d.TimeoutSeconds);
        Assert.Equal(Verdict.Block, d.OnTimeout);
    }

    [Theory]
    [InlineData("rm file.txt")]
    [InlineData("git push origin main")]
    [InlineData("npm test")]
    [InlineData("Get-ChildItem -Recurse")]
    public void DoesNotFlagHarmlessCommands(string command)
    {
        var d = Eval(Repo.DefaultEngine(), Actions.ShellExec, command);
        Assert.Null(d.RuleId);
    }

    [Fact]
    public void ProtectsAgentGuardItself()
    {
        Assert.Equal("protect-agentguard-service", Eval(Repo.DefaultEngine(), Actions.ShellExec, "sc stop AgentGuard").RuleId);
        Assert.Equal("protect-agentguard-service", Eval(Repo.DefaultEngine(), Actions.ShellExec, "Stop-Service -Name AgentGuard").RuleId);
        var pd = Environment.GetEnvironmentVariable("ProgramData") ?? (OperatingSystem.IsWindows() ? @"C:\ProgramData" : "/var/lib");
        var d = Eval(Repo.DefaultEngine(), Actions.FileWrite, Path.Combine(pd, "AgentGuard", "policy.yaml"));
        Assert.Equal("protect-agentguard-files", d.RuleId);
        Assert.Equal(Severity.Critical, d.Severity);
    }

    [Fact]
    public void EnvFileInsideProjectIsFineOutsideAsks()
    {
        var engine = Repo.DefaultEngine();
        Assert.Null(Eval(engine, Actions.FileRead, @"C:\Users\ana\src\app\.env").RuleId);
        var outside = Eval(engine, Actions.FileRead, @"C:\Users\ana\src\other\.env");
        Assert.Equal("env-and-keys-outside-project", outside.RuleId);
        Assert.Equal(Verdict.Ask, outside.Effective);
        Assert.Equal("env-and-keys-outside-project", Eval(engine, Actions.FileRead, @"D:\certs\server.pem").RuleId);
    }

    [Fact]
    public void PersistenceAndDefender()
    {
        var engine = Repo.DefaultEngine();
        Assert.Equal("persistence-autorun", Eval(engine, Actions.ShellExec, @"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d evil.exe").RuleId);
        Assert.Equal("persistence-autorun", Eval(engine, Actions.ProcessStart, "schtasks /create /tn x /tr evil.exe /sc onlogon").RuleId);
        Assert.Equal("defender-tampering", Eval(engine, Actions.ShellExec, "Set-MpPreference -DisableRealtimeMonitoring $true").RuleId);
        Assert.Equal("credential-manager", Eval(engine, Actions.ShellExec, "cmdkey /list").RuleId);
    }

    private sealed class Contacts : IPolicyContext
    {
        public HashSet<string> Seen { get; } = new();
        public bool IsFirstContact(string agentId, string host) => !Seen.Contains(agentId + "|" + host);
    }

    [Fact]
    public void FirstContactEgressLogsWithAlertAndAsksInStrict()
    {
        var ctx = new Contacts();
        var engine = Repo.DefaultEngine();
        var d = Eval(engine, Actions.NetConnect, "evil.example.net:443", ctx: ctx);
        Assert.Equal("first-contact-egress", d.RuleId);
        Assert.Equal(Verdict.Log, d.Effective);
        Assert.True(d.Alert);

        ctx.Seen.Add("claude-code|evil.example.net");
        Assert.Null(Eval(engine, Actions.NetConnect, "evil.example.net:443", ctx: ctx).RuleId);

        Assert.Null(Eval(engine, Actions.NetConnect, "https://api.anthropic.com/v1/messages", ctx: new Contacts()).RuleId);
        Assert.Null(Eval(engine, Actions.NetConnect, "raw.githubusercontent.com:443", ctx: new Contacts()).RuleId);

        var strict = Repo.DefaultEngine(PolicyMode.Strict);
        Assert.Equal(Verdict.Ask, Eval(strict, Actions.NetConnect, "evil.example.net:443", ctx: new Contacts()).Effective);
    }

    [Fact]
    public void ResolvedHostnameInDetailsIsUsed()
    {
        var d = Eval(Repo.DefaultEngine(), Actions.NetConnect, "140.82.112.3:443", ctx: new Contacts(),
            details: new() { ["hostname"] = "github.com" });
        Assert.Null(d.RuleId);
    }

    [Fact]
    public void MonitorModeNeverBlocksButStillAlerts()
    {
        var d = Eval(Repo.DefaultEngine(PolicyMode.Monitor), Actions.FileRead, @"C:\Users\ana\.ssh\id_rsa");
        Assert.Equal(Verdict.Block, d.RuleVerdict);
        Assert.Equal(Verdict.Log, d.Effective);
        Assert.True(d.Alert);
    }

    [Fact]
    public void TrustAndKillSwitch()
    {
        var engine = Repo.DefaultEngine();
        Assert.Equal(Verdict.Block, Eval(engine, Actions.FileRead, "C:/x.txt", trust: "blocked").Effective);
        Assert.Equal(PolicyEngine.TrustBlockedRuleId, Eval(engine, Actions.FileRead, "C:/x.txt", trust: "blocked").RuleId);
        Assert.Equal(Verdict.Allow, Eval(engine, Actions.ShellExec, "rm -rf build", trust: "allowed").Effective);
        // Trusted agents still cannot read secrets.
        Assert.Equal(Verdict.Block, Eval(engine, Actions.FileRead, @"C:\Users\ana\.ssh\id_rsa", trust: "allowed").Effective);
        Assert.Equal(PolicyEngine.KillSwitchRuleId, Eval(engine, Actions.FileRead, "C:/x.txt", kill: true).RuleId);
    }

    [Fact]
    public void McpShellToolsAsk()
    {
        var d = Eval(Repo.DefaultEngine(), Actions.McpCall, "desktop-commander/execute_command", agent: "mcp:desktop-commander");
        Assert.Equal("mcp-shell-tools", d.RuleId);
        Assert.Equal(Verdict.Ask, d.Effective);
        Assert.Null(Eval(Repo.DefaultEngine(), Actions.McpCall, "github/search_repositories", agent: "mcp:github").RuleId);
    }

    [Fact]
    public void DisabledRulesAreSkippedAndFirstMatchWins()
    {
        var yaml = """
            version: 1
            rules:
              - id: off
                enabled: false
                match: { action: file.read }
                verdict: block
              - id: first
                match: { action: "file.*" }
                verdict: ask
              - id: second
                match: { action: file.read }
                verdict: block
            """;
        var r = PolicyParser.Parse(yaml);
        Assert.True(r.Ok);
        var d = new PolicyEngine(r.Document!).Evaluate(new PolicyInput("a", "file.read", "/x"));
        Assert.Equal("first", d.RuleId);
    }

    [Fact]
    public void LinuxHomePathsWork()
    {
        var d = Repo.DefaultEngine().Evaluate(new PolicyInput("claude-code", Actions.FileRead, "/home/ana/.ssh/id_ed25519", null, "/home/ana", "/home/ana/src"));
        Assert.Equal("protect-ssh-keys", d.RuleId);
    }
}

public class PolicyTextTests
{
    [Fact]
    public void SetModeReplacesExistingLine()
    {
        var yaml = Repo.DefaultPolicy;
        var updated = PolicyText.SetMode(yaml, PolicyMode.Monitor);
        Assert.Contains("\nmode: monitor", updated);
        Assert.Equal(PolicyMode.Monitor, PolicyParser.Parse(updated, Repo.PoliciesDir).Document!.Mode);
        Assert.Contains("# AgentGuard default policy", updated);
    }

    [Fact]
    public void AddAllowRuleGoesFirstAndParses()
    {
        var (yaml, id) = PolicyText.AddAllowRule(Repo.DefaultPolicy, "claude-code", Actions.ShellExec, "rm -rf build", "ana");
        var r = PolicyParser.Parse(yaml, Repo.PoliciesDir);
        Assert.True(r.Ok, string.Join("\n", r.Errors.Select(e => e.Message)));
        Assert.Equal(id, r.Document!.Rules[0].Id);
        var engine = new PolicyEngine(r.Document);
        Assert.Equal(Verdict.Allow, engine.Evaluate(new PolicyInput("claude-code", Actions.ShellExec, "rm -rf build")).Effective);
        Assert.Equal(Verdict.Ask, engine.Evaluate(new PolicyInput("claude-code", Actions.ShellExec, "rm -rf src")).Effective);
        // Idempotent.
        var (again, _) = PolicyText.AddAllowRule(yaml, "claude-code", Actions.ShellExec, "rm -rf build", "ana");
        Assert.Equal(yaml, again);
    }

    [Fact]
    public void AddAllowRuleForPathAndZeroIndentList()
    {
        var yaml = "version: 1\nrules:\n- id: a\n  verdict: ask\n  match:\n    action: file.read\n";
        var (updated, _) = PolicyText.AddAllowRule(yaml, "cursor", Actions.FileRead, @"C:\Users\ana\notes\.env", "ana");
        var r = PolicyParser.Parse(updated);
        Assert.True(r.Ok, string.Join("\n", r.Errors.Select(e => e.Message)));
        var engine = new PolicyEngine(r.Document!);
        Assert.Equal(Verdict.Allow, engine.Evaluate(new PolicyInput("cursor", Actions.FileRead, @"C:\Users\ana\notes\.env")).Effective);
        Assert.Equal(Verdict.Ask, engine.Evaluate(new PolicyInput("cursor", Actions.FileRead, @"C:\Users\ana\notes\other")).Effective);
    }

    [Fact]
    public void AddAllowRuleToEmptyRules()
    {
        var (updated, _) = PolicyText.AddAllowRule("version: 1\nmode: enforce\nrules: []\n", "x", "mcp.call", "github/x", "me");
        Assert.True(PolicyParser.Parse(updated).Ok);
    }
}

public class GlobTests
{
    [Theory]
    [InlineData("~/.ssh/**", "C:/Users/ana/.ssh/id_rsa", true)]
    [InlineData("~/.ssh/**", "C:/Users/ana/.ssh", false)]
    [InlineData("**/*.pem", "C:/a/b/c.pem", true)]
    [InlineData("C:/x/*.txt", "C:/x/y/z.txt", false)]
    [InlineData("C:/x/**/z.txt", "C:/x/z.txt", true)]
    [InlineData("%APPDATA%/Claude/*.json", "C:/Users/ana/AppData/Roaming/Claude/claude_desktop_config.json", true)]
    public void PathGlobs(string pattern, string path, bool expected)
    {
        var expanded = Glob.ExpandPattern(pattern, new PathContext(@"C:\Users\ana"));
        Assert.Equal(expected, Glob.IsMatch(expanded, path, pathMode: true));
    }

    [Fact]
    public void NormalizesNtPaths()
    {
        Assert.Equal("C:/Windows/x.dll", Glob.NormalizePath(@"\??\C:\Windows\x.dll"));
        Assert.Equal("C:/a/b", Glob.NormalizePath(@"\\?\C:\a\\b\"));
    }

    [Theory]
    [InlineData("https://api.github.com/repos", "api.github.com")]
    [InlineData("example.com:443", "example.com")]
    [InlineData("[::1]:8080", "::1")]
    [InlineData("10.0.0.1", "10.0.0.1")]
    public void HostExtraction(string target, string host) => Assert.Equal(host, PolicyEngine.HostOf(target));
}
