using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core;
using AgentGuard.Core.Integration;
using AgentGuard.Hook;
using AgentGuard.Service.Tests;

namespace AgentGuard.Tools.Tests;

public class HookTests
{
    private static string Payload(string tool, object input, string cwd = "/repo") => JsonSerializer.Serialize(new
    {
        session_id = "s1",
        transcript_path = "/tmp/t.jsonl",
        cwd,
        permission_mode = "default",
        hook_event_name = "PreToolUse",
        tool_name = tool,
        tool_input = input,
        tool_use_id = "toolu_1",
    });

    private static async Task<(int Code, string Out, string Err)> Run(ServiceFixture f, string payload, bool failOpen = false, McpGate.Decider? decider = null)
    {
        using var api = new AgentGuardClient("http://localhost/", handler: f.Server.CreateHandler());
        var runner = new HookRunner(decider ?? api.DecideAsync, failOpen) { UserProfile = "/home/u", Pid = 777 };
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var code = await runner.RunAsync(payload, stdout, stderr);
        return (code, stdout.ToString(), stderr.ToString());
    }

    private static JsonNode Decision(string stdout) => JsonNode.Parse(stdout)!["hookSpecificOutput"]!;

    [Fact]
    public async Task DeniesWhatPolicyBlocks()
    {
        using var f = new ServiceFixture();
        var (code, stdout, _) = await Run(f, Payload("Read", new { file_path = "~/.ssh/id_rsa" }));
        Assert.Equal(0, code);
        var d = Decision(stdout);
        Assert.Equal("PreToolUse", d["hookEventName"]!.GetValue<string>());
        Assert.Equal("deny", d["permissionDecision"]!.GetValue<string>());
        Assert.StartsWith("Blocked by AgentGuard", d["permissionDecisionReason"]!.GetValue<string>());
    }

    [Fact]
    public async Task StaysSilentWhenAllowedSoClaudeCodePermissionsStillApply()
    {
        using var f = new ServiceFixture();
        var (code, stdout, stderr) = await Run(f, Payload("Bash", new { command = "npm test", description = "run tests" }));
        Assert.Equal(0, code);
        Assert.Equal("", stdout);
        Assert.Equal("", stderr);

        var e = (await f.Client().GetJson("/api/v1/events?action=shell.exec")).GetProperty("items")[0];
        Assert.Equal("npm test", e.GetProperty("target").GetString());
        Assert.Equal("claude-code", e.GetProperty("agentId").GetString());
        Assert.Equal(777, e.GetProperty("pid").GetInt32());
        Assert.Equal("/repo", e.GetProperty("details").GetProperty("cwd").GetString());
        Assert.Equal("toolu_1", e.GetProperty("details").GetProperty("toolUseId").GetString());
    }

    [Fact]
    public async Task McpToolsAreCheckedIncludingTheirArguments()
    {
        using var f = new ServiceFixture();
        var (_, stdout, _) = await Run(f, Payload("mcp__filesystem__read_file", new { path = "/home/u/.aws/credentials" }));
        Assert.Equal("deny", Decision(stdout)["permissionDecision"]!.GetValue<string>());
        var events = await f.Client().GetJson("/api/v1/events?agentId=claude-code");
        Assert.Contains(events.GetProperty("items").EnumerateArray(), e => e.GetProperty("action").GetString() == "mcp.call" && e.GetProperty("target").GetString() == "filesystem/read_file");
    }

    [Fact]
    public async Task RelativePathsResolveAgainstTheSessionDirectory()
    {
        using var f = new ServiceFixture();
        await Run(f, Payload("Write", new { file_path = "src/app.ts", content = "x" }, cwd: "/repo"));
        var e = (await f.Client().GetJson("/api/v1/events?action=file.write")).GetProperty("items")[0];
        Assert.Equal(Path.GetFullPath("/repo/src/app.ts"), e.GetProperty("target").GetString());
    }

    [Fact]
    public async Task ServiceDownFailsClosedOrOpen()
    {
        using var f = new ServiceFixture();
        static Task<DecideResponse> Down(DecideRequest r, CancellationToken ct) => throw new HttpRequestException("refused");
        var closed = await Run(f, Payload("Bash", new { command = "ls" }), decider: Down);
        Assert.Equal("deny", Decision(closed.Out)["permissionDecision"]!.GetValue<string>());
        Assert.Contains("not reachable", closed.Out);

        var open = await Run(f, Payload("Bash", new { command = "ls" }), failOpen: true, decider: Down);
        Assert.Equal(0, open.Code);
        Assert.Equal("", open.Out);
        Assert.Contains("fail-open", open.Err);
    }

    [Fact]
    public async Task UnreadableInputBlocksWithExitCode2()
    {
        using var f = new ServiceFixture();
        var closed = await Run(f, "{oops");
        Assert.Equal(2, closed.Code);
        Assert.Contains("Blocked by AgentGuard", closed.Err);
        Assert.Equal(0, (await Run(f, "{oops", failOpen: true)).Code);
    }

    [Fact]
    public async Task TheRealExecutableFailsClosedWhenTheServiceIsDown()
    {
        var dll = Path.Combine(AppContext.BaseDirectory, "agentguard-hook.dll");
        Assert.True(File.Exists(dll));
        var muxer = Path.Combine(DotnetRoot(), OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet");
        var psi = new ProcessStartInfo(muxer) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        psi.ArgumentList.Add(dll);
        psi.Environment["AGENTGUARD_URL"] = "http://127.0.0.1:9"; // discard port: nothing listens
        psi.Environment["AGENTGUARD_CLIENT_CONFIG"] = Path.Combine(Path.GetTempPath(), "no-such-agentguard-config.json");
        using var p = Process.Start(psi)!;
        await p.StandardInput.WriteAsync(Payload("Bash", new { command = "rm -rf /" }));
        p.StandardInput.Close();
        var stdout = await p.StandardOutput.ReadToEndAsync();
        await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(0, p.ExitCode);
        Assert.Equal("deny", Decision(stdout)["permissionDecision"]!.GetValue<string>());
    }

    private static string DotnetRoot() =>
        Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } r ? r
        : Path.GetFullPath(Path.Combine(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "..", "..", ".."));
}

public class ClaudeSettingsTests
{
    [Fact]
    public void InstallMergesIsIdempotentAndUninstallRestores()
    {
        var dir = Path.Combine(Path.GetTempPath(), "agcs-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "settings.json");
            File.WriteAllText(path, """
                {
                  // user comment
                  "model": "opus",
                  "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "my-linter" } ] } ] },
                }
                """);
            var exe = @"C:\Program Files\AgentGuard\agentguard-hook.exe";
            ClaudeSettings.Install(path, exe);
            ClaudeSettings.Install(path, exe); // twice: still one entry
            var root = JsonNode.Parse(File.ReadAllText(path))!;
            Assert.Equal("opus", root["model"]!.GetValue<string>());
            var pre = root["hooks"]!["PreToolUse"]!.AsArray();
            Assert.Equal(2, pre.Count);
            var ours = pre[1]!;
            Assert.Equal("*", ours["matcher"]!.GetValue<string>());
            Assert.Equal("\"" + exe + "\"", ours["hooks"]![0]!["command"]!.GetValue<string>());
            Assert.Equal(ClaudeSettings.HookTimeoutSeconds, ours["hooks"]![0]!["timeout"]!.GetValue<int>());
            Assert.True(ClaudeSettings.IsInstalled(path));
            Assert.True(File.Exists(path + ".agentguard.bak"));

            Assert.True(ClaudeSettings.Uninstall(path));
            Assert.False(ClaudeSettings.IsInstalled(path));
            var after = JsonNode.Parse(File.ReadAllText(path))!;
            Assert.Equal("my-linter", after["hooks"]!["PreToolUse"]![0]!["hooks"]![0]!["command"]!.GetValue<string>());
            Assert.False(ClaudeSettings.Uninstall(path));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void CreatesAManagedDropInFromNothing()
    {
        var dir = Path.Combine(Path.GetTempPath(), "agcs-" + Guid.NewGuid().ToString("n"));
        try
        {
            var path = Path.Combine(dir, "managed-settings.d", "agentguard.json");
            ClaudeSettings.Install(path, "/opt/agentguard/agentguard-hook");
            Assert.True(ClaudeSettings.IsInstalled(path));
            Assert.True(ClaudeSettings.Uninstall(path));
            Assert.Equal("{}", File.ReadAllText(path).Trim());
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
}
