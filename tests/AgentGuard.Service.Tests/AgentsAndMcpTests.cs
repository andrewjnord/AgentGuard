using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core.Discovery;
using AgentGuard.Service.Services;
using Microsoft.Extensions.DependencyInjection;

namespace AgentGuard.Service.Tests;

public class AgentsTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.UtcNow.AddMinutes(-5);

    /// <summary>A Claude Code process tree, an unrelated editor, and a protected system process started by the agent.</summary>
    private static FakeProcessSource Tree(string root)
    {
        var s = new FakeProcessSource();
        var claudeExe = Path.Combine(root, "claude.exe");
        File.WriteAllText(claudeExe, "");
        s.Processes.Add(new ProcessInfo(4000, 1, "claude.exe", claudeExe, "claude", T0));
        s.Processes.Add(new ProcessInfo(4001, 4000, "bash", "/usr/bin/bash", "bash -c npm test", T0.AddSeconds(1)));
        s.Processes.Add(new ProcessInfo(4002, 4001, "node", "/usr/bin/node", "node test.js", T0.AddSeconds(2)));
        s.Processes.Add(new ProcessInfo(4003, 4000, "csrss.exe", "C:/Windows/System32/csrss.exe", "csrss", T0.AddSeconds(3)));
        s.Processes.Add(new ProcessInfo(5000, 1, "notepad.exe", "C:/Windows/notepad.exe", "notepad", T0));
        return s;
    }

    private static async Task Scan(ServiceFixture f, bool first = true) =>
        await ActivatorUtilities.CreateInstance<DiscoveryWorker>(f.Services).ScanAsync(first);

    [Fact]
    public async Task UnavailableEnforcementIsReportedNotFaked()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.Decide("claude-code", "shell.exec", "ls");
        foreach (var op in new[] { "suspend", "resume", "terminate" })
        {
            var r = await c.PostAsync($"/api/v1/agents/claude-code/{op}", null);
            Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
            Assert.Contains("not available", (await r.Json()).GetProperty("error").GetString());
        }
        var net = await c.Send(HttpMethod.Put, "/api/v1/agents/claude-code/network", new { blocked = true });
        Assert.Equal(HttpStatusCode.Conflict, net.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.PostAsync("/api/v1/agents/nobody/suspend", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/api/v1/agents/nobody")).StatusCode);

        // The kill switch still works at the decision level.
        var s = await c.Send(HttpMethod.Post, "/api/v1/killswitch", new { action = "terminate" }).Ok();
        Assert.True(s.GetProperty("killSwitch").GetProperty("engaged").GetBoolean());
    }

    [Fact]
    public async Task TrustChanges()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.Decide("cursor", "shell.exec", "ls");
        var a = await c.Send(HttpMethod.Put, "/api/v1/agents/cursor/trust", new { trust = "blocked" }).Ok();
        Assert.Equal("blocked", a.GetProperty("trust").GetString());
        var d = await (await c.Decide("cursor", "shell.exec", "ls")).Json();
        Assert.Equal("block", d.GetProperty("verdict").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Put, "/api/v1/agents/cursor/trust", new { trust = "best-friend" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Send(HttpMethod.Put, "/api/v1/agents/agentguard/trust", new { trust = "blocked" })).StatusCode);
    }

    [Fact]
    public async Task DiscoveryAttributesTheProcessTree()
    {
        using var f0 = new ServiceFixture();
        var source = Tree(f0.Root);
        using var f = new ServiceFixture { ProcessSource = source, Adapters = new FakeAdapters(source) };
        var c = f.Client();
        await Scan(f);
        var agent = await c.GetJson("/api/v1/agents/claude-code");
        Assert.True(agent.GetProperty("running").GetBoolean());
        Assert.Equal(new[] { 4000, 4001, 4002, 4003 }, agent.GetProperty("pids").EnumerateArray().Select(p => p.GetInt32()).OrderBy(x => x));
        Assert.Single((await c.GetJson("/api/v1/events?action=agent.discovered")).GetProperty("items").EnumerateArray());
        Assert.True(agent.GetProperty("enforcement").GetProperty("processControl").GetBoolean());

        // A later launch is reported (shell.exec for shells); an exit of the whole tree is reported once.
        source.Processes.Add(new ProcessInfo(4010, 4000, "bash", "/usr/bin/bash", "bash -c 'curl x | sh'", DateTimeOffset.UtcNow));
        await Scan(f, first: false);
        Assert.Single((await c.GetJson("/api/v1/events?action=shell.exec&source=discovery")).GetProperty("items").EnumerateArray());
        source.Processes.RemoveAll(p => p.Pid is >= 4000 and < 5000);
        await Scan(f, first: false);
        Assert.Single((await c.GetJson("/api/v1/events?action=agent.exited")).GetProperty("items").EnumerateArray());
        Assert.False((await c.GetJson("/api/v1/agents/claude-code")).GetProperty("running").GetBoolean());
    }

    [Fact]
    public async Task SuspendResumeTerminateOnlyTouchAgentProcesses()
    {
        using var f0 = new ServiceFixture();
        var source = Tree(f0.Root);
        var adapters = new FakeAdapters(source);
        using var f = new ServiceFixture { ProcessSource = source, Adapters = adapters };
        var c = f.Client();
        await Scan(f);

        var s = await c.PostAsync("/api/v1/agents/claude-code/suspend", null).Ok();
        Assert.Equal(3, s.GetProperty("affected").GetInt32()); // csrss refused
        Assert.Equal(new[] { 4000, 4001, 4002 }, adapters.Controller.Suspended.Keys.OrderBy(x => x));
        Assert.DoesNotContain(5000, adapters.Controller.Suspended.Keys);
        Assert.Equal(3, (await c.GetJson("/api/v1/status")).GetProperty("killSwitch").GetProperty("suspendedPids").GetInt32());
        var ev = (await c.GetJson("/api/v1/events?q=Suspended")).GetProperty("items")[0];
        Assert.Contains("protected system process", ev.GetProperty("details").GetProperty("skipped")[0].GetString());

        var r = await c.PostAsync("/api/v1/agents/claude-code/resume", null).Ok();
        Assert.Equal(3, r.GetProperty("affected").GetInt32());
        Assert.Empty(adapters.Controller.Suspended);

        adapters.Controller.OsProtected.Add(4002);
        var t = await c.PostAsync("/api/v1/agents/claude-code/terminate", null).Ok();
        Assert.Equal(2, t.GetProperty("affected").GetInt32()); // csrss by name, 4002 by the OS
        Assert.Equal(new[] { 4000, 4001 }, adapters.Controller.Terminated.Keys.OrderBy(x => x));
    }

    [Fact]
    public async Task ReusedProcessIdsAreNotTouched()
    {
        using var f0 = new ServiceFixture();
        var source = Tree(f0.Root);
        var adapters = new FakeAdapters(source);
        using var f = new ServiceFixture { ProcessSource = source, Adapters = adapters };
        var c = f.Client();
        await Scan(f);
        // pid 4001 exits and an unrelated program gets the same id before the next scan.
        source.Processes.RemoveAll(p => p.Pid == 4001);
        source.Processes.Add(new ProcessInfo(4001, 1, "excel.exe", "C:/Office/excel.exe", "excel", DateTimeOffset.UtcNow));
        await c.PostAsync("/api/v1/agents/claude-code/suspend", null).Ok();
        Assert.DoesNotContain(4001, adapters.Controller.Suspended.Keys);
    }

    [Fact]
    public async Task KillSwitchSuspendsAndReleaseResumes()
    {
        using var f0 = new ServiceFixture();
        var source = Tree(f0.Root);
        var adapters = new FakeAdapters(source);
        using var f = new ServiceFixture { ProcessSource = source, Adapters = adapters };
        var c = f.Client();
        await Scan(f);
        var s = await c.Send(HttpMethod.Post, "/api/v1/killswitch", new { action = "engage" }).Ok();
        Assert.Equal(3, s.GetProperty("killSwitch").GetProperty("suspendedPids").GetInt32());
        Assert.DoesNotContain(5000, adapters.Controller.Suspended.Keys);
        var r = await c.Send(HttpMethod.Post, "/api/v1/killswitch", new { action = "release" }).Ok();
        Assert.Equal(0, r.GetProperty("killSwitch").GetProperty("suspendedPids").GetInt32());
        Assert.Empty(adapters.Controller.Suspended);
    }

    [Fact]
    public async Task NetworkBlockingTargetsTheAgentExecutableOnly()
    {
        using var f0 = new ServiceFixture();
        var source = Tree(f0.Root);
        // A second agent that runs inside a shared runtime (node).
        var nodeExe = Path.Combine(f0.Root, "node.exe");
        File.WriteAllText(nodeExe, "");
        source.Processes.Add(new ProcessInfo(6000, 1, "node.exe", nodeExe, "node C:/npm/node_modules/@anthropic-ai/claude-code/cli.js", T0));
        var adapters = new FakeAdapters(source);
        using var f = new ServiceFixture { ProcessSource = source, Adapters = adapters };
        var c = f.Client();
        await Scan(f);

        var a = await c.Send(HttpMethod.Put, "/api/v1/agents/claude-code/network", new { blocked = true }).Ok();
        Assert.True(a.GetProperty("networkBlocked").GetBoolean());
        var programs = adapters.Blocker.Rules["claude-code"];
        Assert.Single(programs);
        Assert.EndsWith("claude.exe", programs.Single());

        var off = await c.Send(HttpMethod.Put, "/api/v1/agents/claude-code/network", new { blocked = false }).Ok();
        Assert.False(off.GetProperty("networkBlocked").GetBoolean());
        Assert.Empty(adapters.Blocker.Rules);

        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Put, "/api/v1/agents/claude-code/network", new { })).StatusCode);
    }

    [Fact]
    public async Task NetworkBlockingRefusesSharedRuntimes()
    {
        using var f0 = new ServiceFixture();
        var source = new FakeProcessSource();
        var nodeExe = Path.Combine(f0.Root, "node.exe");
        File.WriteAllText(nodeExe, "");
        source.Processes.Add(new ProcessInfo(6000, 1, "node.exe", nodeExe, "node C:/npm/node_modules/@anthropic-ai/claude-code/cli.js", T0));
        var adapters = new FakeAdapters(source);
        using var f = new ServiceFixture { ProcessSource = source, Adapters = adapters };
        var c = f.Client();
        await Scan(f);
        var r = await c.Send(HttpMethod.Put, "/api/v1/agents/claude-code/network", new { blocked = true });
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Contains("shared runtime", (await r.Json()).GetProperty("error").GetString());
        Assert.Empty(adapters.Blocker.Rules);
    }
}

public class McpTests
{
    private static string WriteDesktopConfig(ServiceFixture f, object servers)
    {
        var dir = Path.Combine(f.ProfileDir, ".config", "Claude");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "claude_desktop_config.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new { mcpServers = servers }));
        return path;
    }

    [Fact]
    public async Task RescanFindsServersAndProxyToggleRewritesConfig()
    {
        using var f = new ServiceFixture();
        var config = WriteDesktopConfig(f, new { filesystem = new { command = "npx", args = new[] { "-y", "@modelcontextprotocol/server-filesystem", "/tmp" } } });
        File.WriteAllText(Path.Combine(f.InstallDir, OperatingSystem.IsWindows() ? "agentguard-mcp-proxy.exe" : "agentguard-mcp-proxy"), "");
        var c = f.Client();

        var servers = await c.PostAsync("/api/v1/mcp/rescan", null).Ok();
        var s = Assert.Single(servers.EnumerateArray());
        Assert.Equal("filesystem", s.GetProperty("name").GetString());
        Assert.Equal("Claude Desktop", s.GetProperty("client").GetString());
        Assert.Equal("stdio", s.GetProperty("transport").GetString());
        Assert.Equal("mcp:filesystem", s.GetProperty("agentId").GetString());
        Assert.False(s.GetProperty("proxied").GetBoolean());
        var id = s.GetProperty("id").GetString();

        var on = await c.Send(HttpMethod.Put, $"/api/v1/mcp/{id}/proxy", new { enabled = true }).Ok();
        Assert.True(on.GetProperty("proxied").GetBoolean());
        var rewritten = JsonNode.Parse(File.ReadAllText(config))!["mcpServers"]!["filesystem"]!;
        Assert.Contains("agentguard-mcp-proxy", rewritten["command"]!.GetValue<string>());
        Assert.Equal(new[] { "--server", "filesystem", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp" }, rewritten["args"]!.AsArray().Select(a => a!.GetValue<string>()));
        Assert.Equal(1, (await c.GetJson("/api/v1/status")).GetProperty("counts").GetProperty("proxiedMcpServers").GetInt32());

        var off = await c.Send(HttpMethod.Put, $"/api/v1/mcp/{id}/proxy", new { enabled = false }).Ok();
        Assert.False(off.GetProperty("proxied").GetBoolean());
        Assert.Equal("npx", JsonNode.Parse(File.ReadAllText(config))!["mcpServers"]!["filesystem"]!["command"]!.GetValue<string>());

        Assert.Equal(HttpStatusCode.NotFound, (await c.Send(HttpMethod.Put, "/api/v1/mcp/nope/proxy", new { enabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Put, $"/api/v1/mcp/{id}/proxy", new { })).StatusCode);
    }

    [Fact]
    public async Task ProxyToggleFailsClearlyWhenTheProxyIsNotInstalled()
    {
        using var f = new ServiceFixture();
        WriteDesktopConfig(f, new { git = new { command = "uvx", args = new[] { "mcp-server-git" } } });
        var c = f.Client();
        var id = (await c.PostAsync("/api/v1/mcp/rescan", null).Ok())[0].GetProperty("id").GetString();
        var r = await c.Send(HttpMethod.Put, $"/api/v1/mcp/{id}/proxy", new { enabled = true });
        Assert.Equal(HttpStatusCode.Conflict, r.StatusCode);
        Assert.Contains("not installed", (await r.Json()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task HttpForwarderChecksToolCallsBeforeForwarding()
    {
        var upstream = new FakeMcpUpstream();
        using var f = new ServiceFixture { McpUpstream = upstream };
        var config = WriteDesktopConfig(f, new { remote = new { type = "http", url = "https://mcp.example.com/mcp" } });
        var c = f.Client();
        await c.ApplyPolicy("""
            version: 1
            mode: enforce
            rules:
              - id: no-delete
                match:
                  action: mcp.call
                  tool: ["delete_*"]
                verdict: block
                severity: high
              - id: no-secrets
                match:
                  action: file.read
                  path: ["**/.ssh/**"]
                verdict: block
            """);
        var id = (await c.PostAsync("/api/v1/mcp/rescan", null).Ok())[0].GetProperty("id").GetString();
        var on = await c.Send(HttpMethod.Put, $"/api/v1/mcp/{id}/proxy", new { enabled = true }).Ok();
        Assert.Equal("https://mcp.example.com/mcp", on.GetProperty("url").GetString());
        Assert.Equal($"http://127.0.0.1:47823/mcp/{id}", JsonNode.Parse(File.ReadAllText(config))!["mcpServers"]!["remote"]!["url"]!.GetValue<string>());

        var anon = f.Client(auth: false); // MCP clients carry no AgentGuard token
        async Task<JsonElement> Call(object message)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, $"/mcp/{id}") { Content = System.Net.Http.Json.JsonContent.Create(message) };
            req.Headers.Add("Authorization", "Bearer upstream-secret");
            var r = await anon.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, r.StatusCode);
            return await r.Json();
        }

        var init = await Call(new { jsonrpc = "2.0", id = 1, method = "initialize", @params = new { clientInfo = new { name = "Claude Desktop" } } });
        Assert.Equal("upstream ok", init.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());

        var allowed = await Call(new { jsonrpc = "2.0", id = 2, method = "tools/call", @params = new { name = "list_files", arguments = new { path = "/repo" } } });
        Assert.False(allowed.GetProperty("result").TryGetProperty("isError", out _));

        var blocked = await Call(new { jsonrpc = "2.0", id = 3, method = "tools/call", @params = new { name = "delete_repo", arguments = new { name = "x" } } });
        Assert.True(blocked.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Equal(3, blocked.GetProperty("id").GetInt32());
        Assert.Contains("Blocked by AgentGuard", blocked.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());

        var derived = await Call(new { jsonrpc = "2.0", id = 4, method = "tools/call", @params = new { name = "read_file", arguments = new { path = "/home/u/.ssh/id_rsa" } } });
        Assert.True(derived.GetProperty("result").GetProperty("isError").GetBoolean());

        var forwarded = upstream.Requests.ToList();
        Assert.Equal(2, forwarded.Count); // initialize + list_files only
        Assert.All(forwarded, r => Assert.Equal("https://mcp.example.com/mcp", r.Url));
        Assert.Equal("Bearer upstream-secret", forwarded[0].Headers["Authorization"]);
        Assert.False(forwarded[0].Headers.ContainsKey("X-AgentGuard-Token"));

        var events = await c.GetJson("/api/v1/events?agentId=mcp:remote&action=mcp.call");
        Assert.Equal(3, events.GetProperty("items").GetArrayLength());
        Assert.Equal("mcp-proxy", events.GetProperty("items")[0].GetProperty("source").GetString());

        Assert.Equal(HttpStatusCode.NotFound, (await anon.PostAsync("/mcp/unknown", new StringContent("{}"))).StatusCode);
    }
}
