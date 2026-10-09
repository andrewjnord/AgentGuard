using System.Text.Json;
using AgentGuard.Cli;
using AgentGuard.Core.Integration;
using AgentGuard.Service.Tests;
using Microsoft.Data.Sqlite;

namespace AgentGuard.Tools.Tests;

public class CliTests
{
    private sealed record Result(int Code, string Out, string Err);

    private static async Task<Result> Run(ServiceFixture f, params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var cli = new AdminCli(stdout, stderr, (url, token) => new AgentGuardClient("http://localhost/", token, handler: f.Server.CreateHandler(), actor: "cli"));
        var all = args.Concat(new[] { "--data-dir", f.DataDir }).ToArray();
        var code = await cli.RunAsync(all);
        return new Result(code, stdout.ToString(), stderr.ToString());
    }

    private static string Temp(ServiceFixture f, string name, string content)
    {
        var p = Path.Combine(f.Root, name);
        File.WriteAllText(p, content);
        return p;
    }

    [Fact]
    public async Task StatusReadsTheTokenFromTheDataDirectory()
    {
        using var f = new ServiceFixture();
        _ = f.Client(); // start the service so it writes admin.token
        var r = await Run(f, "status");
        Assert.Equal(0, r.Code);
        Assert.Contains("Mode:            enforce", r.Out);
        Assert.Contains("Kill switch:     off", r.Out);
        Assert.Contains("not verified yet", r.Out);

        var json = await Run(f, "status", "--json");
        Assert.Equal("enforce", JsonDocument.Parse(json.Out).RootElement.GetProperty("mode").GetString());
    }

    [Fact]
    public async Task ValidatesPoliciesOfflineWithFileLineColumnErrors()
    {
        using var f = new ServiceFixture();
        _ = f.Client(); // start the service so it writes admin.token
        var good = Temp(f, "good.yaml", Policies.AskShell);
        var r = await Run(f, "policy", "validate", good);
        Assert.Equal(0, r.Code);
        Assert.Contains("valid (4 rules)", r.Out);

        var bad = Temp(f, "bad.yaml", "version: 1\nmode: enforce\nrules:\n  - id: x\n    verdict: perhaps\n");
        var b = await Run(f, "policy", "validate", bad);
        Assert.Equal(ExitCodes.Failed, b.Code);
        Assert.Matches(@"bad\.yaml:5:\d+: error: ", b.Err);

        var server = await Run(f, "policy", "validate", bad, "--server");
        Assert.Equal(ExitCodes.Failed, server.Code);
        Assert.Contains("bad.yaml:5:", server.Err);
    }

    [Fact]
    public async Task AppliesAndShowsPolicies()
    {
        using var f = new ServiceFixture();
        _ = f.Client(); // start the service so it writes admin.token
        var applied = await Run(f, "policy", "apply", Temp(f, "p.yaml", Policies.AskShell));
        Assert.Equal(0, applied.Code);
        Assert.Contains("Applied policy v2 (4 rules, mode enforce)", applied.Out);
        Assert.Equal("cli", (await f.Client().GetJson("/api/v1/policy")).GetProperty("appliedBy").GetString());

        var shown = await Run(f, "policy", "show");
        Assert.Equal(Policies.AskShell, shown.Out);
        Assert.Contains("# policy v2", shown.Err);
        Assert.Contains("protect-ssh-keys", (await Run(f, "policy", "show", "--version", "1")).Out);

        var rejected = await Run(f, "policy", "apply", Temp(f, "broken.yaml", "rules: ["));
        Assert.Equal(ExitCodes.Failed, rejected.Code);
        Assert.Contains("was not applied", rejected.Err);
    }

    [Fact]
    public async Task ModeAndKillSwitch()
    {
        using var f = new ServiceFixture();
        _ = f.Client(); // start the service so it writes admin.token
        Assert.Contains("Mode is now monitor", (await Run(f, "mode", "monitor")).Out);
        Assert.Contains("Kill switch engaged", (await Run(f, "killswitch", "engage")).Out);
        Assert.True((await f.Client().GetJson("/api/v1/status")).GetProperty("killSwitch").GetProperty("engaged").GetBoolean());
        Assert.Contains("Kill switch released", (await Run(f, "killswitch", "release")).Out);
        Assert.Equal(ExitCodes.Usage, (await Run(f, "mode", "loud")).Code);
        var events = await f.Client().GetJson("/api/v1/events?action=killswitch");
        Assert.Equal("cli", events.GetProperty("items")[0].GetProperty("details").GetProperty("by").GetString());
    }

    [Fact]
    public async Task ExportsToAFileOrStdout()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.Decide("claude-code", "shell.exec", "npm test");
        await c.Decide("cursor", "shell.exec", "ls");
        var file = Path.Combine(f.Root, "out.ndjson");
        var r = await Run(f, "export", "--format", "ocsf", "--agent", "claude-code", "-o", file);
        Assert.Equal(0, r.Code);
        Assert.Single(File.ReadAllLines(file));
        Assert.Contains("Exported 1 event (ocsf", r.Err);

        var cef = await Run(f, "export", "--format=cef", "--from", DateTimeOffset.UtcNow.AddHours(-1).ToString("O"));
        Assert.All(cef.Out.Split('\n', StringSplitOptions.RemoveEmptyEntries), l => Assert.StartsWith("CEF:0|", l));
        Assert.Equal(ExitCodes.Usage, (await Run(f, "export", "--format", "pdf")).Code);
        Assert.Equal(ExitCodes.Usage, (await Run(f, "export", "--from", "someday")).Code);
    }

    [Fact]
    public async Task VerifyOnlineAndOfflineDetectTampering()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        for (var i = 0; i < 3; i++) await c.Decide("claude-code", "shell.exec", $"echo {i}");
        var ok = await Run(f, "verify");
        Assert.Equal(0, ok.Code);
        Assert.Contains("Audit log intact", ok.Out);
        Assert.Equal(0, (await Run(f, "verify", "--offline")).Code);

        using (var db = new SqliteConnection($"Data Source={Path.Combine(f.DataDir, "agentguard.db")};Pooling=false"))
        {
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "UPDATE events SET target='edited' WHERE id=(SELECT MAX(id) FROM events WHERE action='shell.exec')";
            cmd.ExecuteNonQuery();
        }
        var bad = await Run(f, "verify");
        Assert.Equal(ExitCodes.IntegrityFailed, bad.Code);
        Assert.Contains("INTEGRITY CHECK FAILED", bad.Err);
        Assert.Equal(ExitCodes.IntegrityFailed, (await Run(f, "verify", "--offline")).Code);
    }

    [Fact]
    public async Task CleanupRestoresProxiedMcpConfigs()
    {
        using var f = new ServiceFixture();
        var dir = Path.Combine(f.ProfileDir, ".config", "Claude");
        Directory.CreateDirectory(dir);
        var config = Path.Combine(dir, "claude_desktop_config.json");
        File.WriteAllText(config, JsonSerializer.Serialize(new
        {
            mcpServers = new Dictionary<string, object>
            {
                ["fs"] = new { command = "npx", args = new[] { "-y", "server-fs" } },
                ["remote"] = new { type = "http", url = "https://mcp.example.com/mcp" },
            },
        }));
        File.WriteAllText(Path.Combine(f.InstallDir, OperatingSystem.IsWindows() ? "agentguard-mcp-proxy.exe" : "agentguard-mcp-proxy"), "");
        var c = f.Client();
        foreach (var s in (await c.PostAsync("/api/v1/mcp/rescan", null).Ok()).EnumerateArray())
            await c.Send(HttpMethod.Put, $"/api/v1/mcp/{s.GetProperty("id").GetString()}/proxy", new { enabled = true }).Ok();
        Assert.Contains("agentguard-mcp-proxy", File.ReadAllText(config));
        Assert.Contains("127.0.0.1:47823/mcp/", File.ReadAllText(config));

        var r = await Run(f, "cleanup-integrations", "--profiles", f.ProfileDir, "--keep-hook");
        Assert.Equal(0, r.Code);
        Assert.Contains("Restored 2 integrations", r.Out);
        var after = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(config))!["mcpServers"]!;
        Assert.Equal("npx", after["fs"]!["command"]!.GetValue<string>());
        Assert.Equal("https://mcp.example.com/mcp", after["remote"]!["url"]!.GetValue<string>());
    }

    [Fact]
    public async Task ErrorsAndUsage()
    {
        using var f = new ServiceFixture();
        Assert.Equal(ExitCodes.Usage, (await Run(f, "frobnicate")).Code);
        Assert.Equal(ExitCodes.Usage, (await Run(f, "status", "--bogus")).Code);
        Assert.Equal(ExitCodes.Usage, (await Run(f, "policy", "validate")).Code);
        Assert.Contains("Exit codes", (await Run(f, "help")).Out);

        // No token file yet (service never started in this fixture).
        var noToken = await Run(f, "status");
        Assert.Equal(ExitCodes.Failed, noToken.Code);
        Assert.Contains("No admin token", noToken.Err);

        // Wrong token.
        _ = f.Client();
        Assert.Contains("rejected the admin token", (await Run(f, "status", "--token", "wrong")).Err);

        // Nothing listening.
        var stderr = new StringWriter();
        var down = await new AdminCli(new StringWriter(), stderr).RunAsync(new[] { "status", "--url", "http://127.0.0.1:9", "--token", "x" });
        Assert.Equal(ExitCodes.Unreachable, down);
        Assert.Contains("not reachable", stderr.ToString());
    }
}
