using System.Net;
using System.Text.Json;

namespace AgentGuard.Service.Tests;

public class SecurityTests
{
    [Fact]
    public async Task HealthAndDecideNeedNoToken_EverythingElseDoes()
    {
        using var f = new ServiceFixture();
        var anon = f.Client(auth: false);
        var health = await anon.GetJson("/api/v1/health");
        Assert.True(health.GetProperty("ok").GetBoolean());
        Assert.Equal("0.1.0", health.GetProperty("version").GetString());

        Assert.Equal(HttpStatusCode.OK, (await anon.Decide("claude-code", "shell.exec", "ls")).StatusCode);
        foreach (var path in new[] { "/api/v1/status", "/api/v1/agents", "/api/v1/events", "/api/v1/policy", "/api/v1/settings", "/api/v1/export?format=json", "/api/v1/stream" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.Send(HttpMethod.Post, "/api/v1/killswitch", new { action = "engage" })).StatusCode);
    }

    [Fact]
    public async Task WrongTokenIsRejected_QueryTokenIsAccepted()
    {
        using var f = new ServiceFixture();
        var c = f.Client(auth: false);
        c.DefaultRequestHeaders.Add("X-AgentGuard-Token", "nope");
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/v1/status")).StatusCode);
        var anon = f.Client(auth: false);
        Assert.Equal(HttpStatusCode.OK, (await anon.GetAsync($"/api/v1/status?token={ServiceFixture.Token}")).StatusCode);
        var body = await (await c.GetAsync("/api/v1/status")).Json();
        Assert.Contains("token", body.GetProperty("error").GetString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ForeignOriginAndHostAreRejected()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var cross = new HttpRequestMessage(HttpMethod.Post, "/api/v1/decide") { Content = System.Net.Http.Json.JsonContent.Create(new { agentId = "x", action = "a", target = "t", source = "hook" }) };
        cross.Headers.Add("Origin", "https://evil.example");
        Assert.Equal(HttpStatusCode.Forbidden, (await c.SendAsync(cross)).StatusCode);

        var same = new HttpRequestMessage(HttpMethod.Get, "/api/v1/status");
        same.Headers.Add("Origin", "http://127.0.0.1:47823");
        Assert.Equal(HttpStatusCode.OK, (await c.SendAsync(same)).StatusCode);

        var rebinding = new HttpRequestMessage(HttpMethod.Get, "/api/v1/health");
        rebinding.Headers.Host = "attacker.example:47823";
        Assert.Equal(HttpStatusCode.Forbidden, (await c.SendAsync(rebinding)).StatusCode);
    }

    [Fact]
    public async Task SecurityHeadersAndUnknownRoutes()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var r = await c.GetAsync("/api/v1/status");
        Assert.Equal("nosniff", r.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", r.Headers.GetValues("X-Frame-Options").Single());

        var unknown = await c.GetAsync("/api/v1/nope");
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.True((await unknown.Json()).TryGetProperty("error", out _));

        var page = await c.GetAsync("/timeline");
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal("text/html", page.Content.Headers.ContentType?.MediaType);
        Assert.Contains("frame-ancestors 'none'", page.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Fact]
    public async Task MalformedJsonGetsA400WithAnError()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var r = await c.PostAsync("/api/v1/decide", new StringContent("{not json", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.True((await r.Json()).TryGetProperty("error", out _));
    }

    [Fact]
    public void TokenFileIsWrittenToTheDataDirectory()
    {
        using var f = new ServiceFixture();
        _ = f.Client();
        Assert.Equal(ServiceFixture.Token, File.ReadAllText(Path.Combine(f.DataDir, "admin.token")));
        var client = Core.Integration.ClientConfig.Load(Path.Combine(f.DataDir, "public", "client.json"));
        Assert.Equal("closed", client.FailMode);
        Assert.Equal(47823, client.Port);
    }
}

public class StatusAndModeTests
{
    [Fact]
    public async Task StatusHasTheDocumentedShape()
    {
        using var f = new ServiceFixture();
        var s = await f.Client().GetJson("/api/v1/status");
        Assert.Equal("enforce", s.GetProperty("mode").GetString());
        Assert.True(s.GetProperty("devMode").GetBoolean());
        Assert.EndsWith("Z", s.GetProperty("startedAt").GetString());
        foreach (var k in new[] { "agents", "activeAgents", "mcpServers", "proxiedMcpServers", "eventsToday", "blockedToday", "askedToday", "openAlerts", "pendingApprovals" })
            Assert.Equal(JsonValueKind.Number, s.GetProperty("counts").GetProperty(k).ValueKind);
        Assert.False(s.GetProperty("killSwitch").GetProperty("engaged").GetBoolean());
        Assert.Equal(JsonValueKind.Null, s.GetProperty("integrity").GetProperty("ok").ValueKind);
        var caps = s.GetProperty("capabilities");
        Assert.False(caps.GetProperty("processControl").GetBoolean());
        Assert.True(caps.GetProperty("hooks").GetBoolean());
    }

    [Fact]
    public async Task ModeChangesAreAppliedVersionedAndAudited()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var before = (await c.GetJson("/api/v1/policy")).GetProperty("version").GetInt32();
        var req = new HttpRequestMessage(HttpMethod.Put, "/api/v1/mode") { Content = System.Net.Http.Json.JsonContent.Create(new { mode = "monitor" }) };
        req.Headers.Add("X-AgentGuard-Actor", "cli");
        var s = await (await c.SendAsync(req)).Json();
        Assert.Equal("monitor", s.GetProperty("mode").GetString());

        var policy = await c.GetJson("/api/v1/policy");
        Assert.Equal(before + 1, policy.GetProperty("version").GetInt32());
        Assert.Equal("cli", policy.GetProperty("appliedBy").GetString());
        Assert.Contains("mode: monitor", policy.GetProperty("yaml").GetString());

        var events = await c.GetJson("/api/v1/events?action=policy.changed");
        Assert.Contains(events.GetProperty("items").EnumerateArray(), e => e.GetProperty("target").GetString() == "Mode changed to monitor");

        // Monitor mode never blocks.
        var d = await (await c.Decide("claude-code", "file.read", "/home/u/.ssh/id_rsa", userProfile: "/home/u")).Json();
        Assert.Equal("allow", d.GetProperty("verdict").GetString());
        Assert.Equal("block", d.GetProperty("policyVerdict").GetString());

        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Put, "/api/v1/mode", new { mode = "loud" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Put, "/api/v1/mode", new { mode = "1" })).StatusCode);
    }

    [Fact]
    public async Task ActivityReturnsHourlyBucketsAndTopAgents()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.Decide("claude-code", "shell.exec", "ls");
        await c.Decide("claude-code", "file.read", "/home/u/.ssh/id_rsa", userProfile: "/home/u");
        await c.Decide("cursor", "shell.exec", "pwd");
        var a = await c.GetJson("/api/v1/stats/activity?hours=6");
        var buckets = a.GetProperty("buckets").EnumerateArray().ToList();
        Assert.Equal(6, buckets.Count);
        Assert.True(DateTimeOffset.Parse(buckets[0].GetProperty("ts").GetString()!) < DateTimeOffset.Parse(buckets[^1].GetProperty("ts").GetString()!));
        Assert.Equal(3, buckets.Sum(b => b.GetProperty("total").GetInt32()));
        Assert.Equal(1, buckets.Sum(b => b.GetProperty("blocked").GetInt32()));
        var top = a.GetProperty("topAgents").EnumerateArray().ToList();
        Assert.Equal("claude-code", top[0].GetProperty("agentId").GetString());
        Assert.Equal(2, top[0].GetProperty("total").GetInt32());
    }
}
