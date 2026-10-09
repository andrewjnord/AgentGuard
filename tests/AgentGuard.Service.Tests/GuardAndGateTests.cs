using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Integration;
using AgentGuard.Service.Platform;
using AgentGuard.Service.Services;

namespace AgentGuard.Service.Tests;

public class EnforcementGuardTests
{
    private static readonly DateTimeOffset T = DateTimeOffset.UtcNow.AddMinutes(-1);

    private static AttributedProcess Agent(int pid, string name, string agentId = "claude-code") =>
        new(new ProcessInfo(pid, 1, name, "/x/" + name, name, T), agentId, "Claude Code", "cli", null, false, false, false);

    [Theory]
    [InlineData("csrss.exe")]
    [InlineData("lsass.exe")]
    [InlineData("svchost.exe")]
    [InlineData("explorer.exe")]
    [InlineData("MsMpEng.exe")]
    [InlineData("systemd")]
    [InlineData("agentguard-mcp-proxy.exe")]
    public void ProtectedProcessesAreRefusedEvenWhenAttributed(string name)
    {
        var source = new FakeProcessSource();
        source.Processes.Add(new ProcessInfo(900, 1, name, "/x/" + name, name, T));
        var why = EnforcementGuard.ProcessRefusal(Agent(900, name), 900, new FakeProcessController(source), new ProcessTarget(900, T, name, "/x/" + name));
        Assert.NotNull(why);
    }

    [Fact]
    public void RefusesUnattributedReusedSelfAndLowPids()
    {
        var source = new FakeProcessSource();
        var c = new FakeProcessController(source);
        Assert.Equal("not attributed to an AI agent", EnforcementGuard.ProcessRefusal(null, 900, c, new ProcessTarget(900, T, "x", null)));
        Assert.Equal("system process", EnforcementGuard.ProcessRefusal(Agent(4, "x"), 4, c, new ProcessTarget(4, T, "x", null)));
        Assert.Equal("AgentGuard itself", EnforcementGuard.ProcessRefusal(Agent(Environment.ProcessId, "x"), Environment.ProcessId, c, new ProcessTarget(Environment.ProcessId, T, "x", null)));
        Assert.Contains("reused", EnforcementGuard.ProcessRefusal(Agent(900, "node"), 900, c, new ProcessTarget(900, T.AddSeconds(5), "node", null)));
        Assert.Equal("process has exited", EnforcementGuard.ProcessRefusal(Agent(900, "node"), 900, c, null));
        Assert.Equal("AgentGuard itself", EnforcementGuard.ProcessRefusal(Agent(900, "x", "agentguard"), 900, c, new ProcessTarget(900, T, "x", null)));
        c.OsProtected.Add(901);
        Assert.Contains("critical", EnforcementGuard.ProcessRefusal(Agent(901, "node"), 901, c, new ProcessTarget(901, T, "node", null)));
        Assert.Null(EnforcementGuard.ProcessRefusal(Agent(902, "node"), 902, c, new ProcessTarget(902, T, "node", null)));
    }

    [Fact]
    public void FirewallProgramsExcludeSharedAndSystemPrograms()
    {
        var dir = Path.Combine(Path.GetTempPath(), "agfw-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        try
        {
            var cursor = Path.Combine(dir, "Cursor.exe");
            var node = Path.Combine(dir, "node.exe");
            var webview = Path.Combine(dir, "msedgewebview2.exe");
            foreach (var p in new[] { cursor, node, webview }) File.WriteAllText(p, "");
            var (allowed, refused) = EnforcementGuard.FirewallPrograms(new[] { cursor, cursor, node, webview, "relative.exe", Path.Combine(dir, "missing.exe"), null, "/usr/bin/curl" });
            Assert.Equal(new[] { cursor }, allowed);
            Assert.Equal(5, refused.Count);
            Assert.Contains(refused, r => r.Contains("shared runtime") && r.Contains("node.exe"));
            Assert.Contains(refused, r => r.Contains("does not exist"));
            Assert.Contains(refused, r => r.Contains("not an absolute path"));
        }
        finally { Directory.Delete(dir, true); }
    }
}

public class McpGateTests
{
    private sealed class Recorder
    {
        public List<DecideRequest> Seen { get; } = new();
        public Func<DecideRequest, bool> Allow { get; set; } = _ => true;

        public Task<DecideResponse> Decide(DecideRequest r, CancellationToken ct)
        {
            Seen.Add(r);
            var ok = Allow(r);
            return Task.FromResult(new DecideResponse { Verdict = ok ? "allow" : "block", Reason = ok ? "ok" : "Blocked by AgentGuard: no.", EventId = Seen.Count });
        }
    }

    [Fact]
    public async Task NonToolMessagesPassThroughUnchanged()
    {
        var rec = new Recorder();
        var gate = new McpGate("fs", rec.Decide);
        const string msg = """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""";
        var r = await gate.CheckAsync(msg);
        Assert.Equal(msg, r.Forward);
        Assert.Null(r.Reply);
        Assert.Empty(rec.Seen);
        Assert.Equal("not json", (await gate.CheckAsync("not json")).Forward);
    }

    [Fact]
    public async Task ToolCallsAreCheckedWithDerivedChecks()
    {
        var rec = new Recorder();
        var gate = new McpGate("fs", rec.Decide) { UserProfile = "/home/u", Pid = 42 };
        await gate.CheckAsync("""{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"clientInfo":{"name":"Cursor"}}}""");
        var r = await gate.CheckAsync("""{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"write_file","arguments":{"path":"/repo/x.txt","content":"hi"}}}""");
        Assert.NotNull(r.Forward);
        Assert.Equal(2, rec.Seen.Count);
        Assert.Equal(Actions.McpCall, rec.Seen[0].Action);
        Assert.Equal("fs/write_file", rec.Seen[0].Target);
        Assert.Equal("mcp:fs", rec.Seen[0].AgentId);
        Assert.Equal("Cursor", rec.Seen[0].Details!["client"]);
        Assert.Equal(Actions.FileWrite, rec.Seen[1].Action);
        Assert.Equal("/repo/x.txt", rec.Seen[1].Target);
        Assert.Equal(42, rec.Seen[1].Pid);
        Assert.Equal(EventSources.McpProxy, rec.Seen[1].Source);
    }

    [Fact]
    public async Task BlockedCallsGetAnErrorResultWithTheSameId()
    {
        var rec = new Recorder { Allow = r => r.Action != Actions.FileRead };
        var gate = new McpGate("fs", rec.Decide);
        var r = await gate.CheckAsync("""{"jsonrpc":"2.0","id":"req-7","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}""");
        Assert.Null(r.Forward);
        var reply = JsonNode.Parse(r.Reply!)!;
        Assert.Equal("req-7", reply["id"]!.GetValue<string>());
        Assert.True(reply["result"]!["isError"]!.GetValue<bool>());
        Assert.Contains("Blocked by AgentGuard", reply["result"]!["content"]![0]!["text"]!.GetValue<string>());
    }

    [Fact]
    public async Task UnreachableServiceFailsClosedByDefaultAndOpenWhenAsked()
    {
        static Task<DecideResponse> Down(DecideRequest r, CancellationToken ct) => throw new HttpRequestException("connection refused");
        const string call = """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}""";
        var closed = await new McpGate("s", Down).CheckAsync(call);
        Assert.Null(closed.Forward);
        Assert.Contains("not reachable", closed.Reply);
        var open = await new McpGate("s", Down, failOpen: true).CheckAsync(call);
        Assert.Equal(call, open.Forward);
    }

    [Fact]
    public async Task BatchesForwardAllowedAndAnswerBlocked()
    {
        var rec = new Recorder { Allow = r => !r.Target.EndsWith("/bad") };
        var gate = new McpGate("s", rec.Decide);
        var r = await gate.CheckAsync("""[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"good"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bad"}},{"jsonrpc":"2.0","method":"notifications/initialized"}]""");
        var forwarded = JsonNode.Parse(r.Forward!)!.AsArray();
        Assert.Equal(2, forwarded.Count);
        var replies = JsonNode.Parse(r.Reply!)!.AsArray();
        Assert.Equal(2, Assert.Single(replies)!["id"]!.GetValue<int>());
    }
}
