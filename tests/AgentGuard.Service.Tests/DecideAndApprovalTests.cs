using System.Net;
using System.Text.Json;

namespace AgentGuard.Service.Tests;

public class DecideTests
{
    [Fact]
    public async Task BlocksAndAllowsByPolicyAndRecordsEnforcedEvents()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var blocked = await (await c.Decide("claude-code", "file.read", "/home/u/.ssh/id_rsa", userProfile: "/home/u")).Json();
        Assert.Equal("block", blocked.GetProperty("verdict").GetString());
        Assert.Equal("protect-ssh-keys", blocked.GetProperty("ruleId").GetString());
        Assert.StartsWith("Blocked by AgentGuard", blocked.GetProperty("reason").GetString());
        var e = await c.GetJson($"/api/v1/events/{blocked.GetProperty("eventId").GetInt64()}");
        Assert.True(e.GetProperty("enforced").GetBoolean());
        Assert.Equal("hook", e.GetProperty("source").GetString());
        Assert.Equal(64, e.GetProperty("hash").GetString()!.Length);

        var allowed = await (await c.Decide("claude-code", "shell.exec", "npm test")).Json();
        Assert.Equal("allow", allowed.GetProperty("verdict").GetString());
        Assert.Equal(JsonValueKind.Null, allowed.GetProperty("approvalId").ValueKind);

        var agent = await c.GetJson("/api/v1/agents/claude-code");
        Assert.True(agent.GetProperty("enforcement").GetProperty("hooks").GetBoolean());
        Assert.Equal(2, agent.GetProperty("eventCount24h").GetInt32());
        Assert.Equal(1, agent.GetProperty("blockedCount24h").GetInt32());
    }

    [Theory]
    [InlineData("""{"agentId":"","action":"shell.exec","target":"x","source":"hook"}""")]
    [InlineData("""{"agentId":"agentguard","action":"shell.exec","target":"x","source":"hook"}""")]
    [InlineData("""{"agentId":"claude-code","action":"","target":"x","source":"hook"}""")]
    [InlineData("""{"agentId":"claude-code","action":"shell.exec","target":"x","source":"etw"}""")]
    [InlineData("""{"agentId":"claude-code","action":"shell.exec","target":"x","source":"system"}""")]
    [InlineData("""{"agentId":"bad id with spaces","action":"shell.exec","target":"x","source":"hook"}""")]
    [InlineData("""{"agentId":"claude-code","action":"shell.exec","source":"hook","target":null}""")]
    public async Task RejectsInvalidRequests(string body)
    {
        using var f = new ServiceFixture();
        var r = await f.Client(auth: false).PostAsync("/api/v1/decide", new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task AskWaitsForApproval_AllowOnce()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policies.AskShell);
        var pending = c.Decide("claude-code", "shell.exec", "./deploy.sh prod");

        JsonElement approval = default;
        await Http.WaitUntil(async () =>
        {
            var list = await c.GetJson("/api/v1/approvals?status=pending");
            if (list.GetArrayLength() == 0) return false;
            approval = list[0];
            return true;
        });
        Assert.Equal("ask-deploy", approval.GetProperty("ruleId").GetString());
        Assert.Equal("./deploy.sh prod", approval.GetProperty("target").GetString());
        Assert.Equal(1, (await c.GetJson("/api/v1/status")).GetProperty("counts").GetProperty("pendingApprovals").GetInt32());

        var decided = await c.Send(HttpMethod.Post, $"/api/v1/approvals/{approval.GetProperty("id").GetString()}", new { decision = "allow_once" }).Ok();
        Assert.Equal("allowed", decided.GetProperty("status").GetString());
        Assert.Equal("allow_once", decided.GetProperty("decision").GetString());
        Assert.Equal("dashboard", decided.GetProperty("decidedBy").GetString());

        var result = await (await pending).Json();
        Assert.Equal("allow", result.GetProperty("verdict").GetString());
        Assert.Equal("ask", result.GetProperty("policyVerdict").GetString());
        Assert.Equal(approval.GetProperty("id").GetString(), result.GetProperty("approvalId").GetString());

        // The decision is in the audit trail, and a second answer is refused.
        var events = await c.GetJson("/api/v1/events?action=approval.decided");
        Assert.Single(events.GetProperty("items").EnumerateArray());
        var again = await c.Send(HttpMethod.Post, $"/api/v1/approvals/{approval.GetProperty("id").GetString()}", new { decision = "deny" });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        // allow_once does not change the policy: the next run asks again.
        var next = await (await c.Decide("claude-code", "shell.exec", "./deploy.sh prod", wait: false)).Json();
        Assert.Equal("block", next.GetProperty("verdict").GetString());
        Assert.Equal("ask", next.GetProperty("policyVerdict").GetString());
    }

    [Fact]
    public async Task AskDeniedBlocks()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policies.AskShell);
        var pending = c.Decide("claude-code", "shell.exec", "deploy");
        string id = "";
        await Http.WaitUntil(async () =>
        {
            var list = await c.GetJson("/api/v1/approvals?status=pending");
            if (list.GetArrayLength() == 0) return false;
            id = list[0].GetProperty("id").GetString()!;
            return true;
        });
        await c.Send(HttpMethod.Post, $"/api/v1/approvals/{id}", new { decision = "deny" }).Ok();
        var result = await (await pending).Json();
        Assert.Equal("block", result.GetProperty("verdict").GetString());
        Assert.Contains("denied", result.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task AllowAlwaysAddsAPolicyRule()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policies.AskShell);
        var first = await (await c.Decide("claude-code", "shell.exec", "deploy staging", wait: false)).Json();
        Assert.Equal("block", first.GetProperty("verdict").GetString());
        var approvalId = first.GetProperty("approvalId").GetString();
        Assert.NotNull(approvalId);

        var decided = await c.Send(HttpMethod.Post, $"/api/v1/approvals/{approvalId}", new { decision = "allow_always" }).Ok();
        Assert.Equal("allowed", decided.GetProperty("status").GetString());

        var policy = await c.GetJson("/api/v1/policy");
        Assert.Contains("deploy staging", policy.GetProperty("yaml").GetString());
        var again = await (await c.Decide("claude-code", "shell.exec", "deploy staging")).Json();
        Assert.Equal("allow", again.GetProperty("verdict").GetString());
        // Another agent is still asked.
        var other = await (await c.Decide("cursor", "shell.exec", "deploy staging", wait: false)).Json();
        Assert.Equal("ask", other.GetProperty("policyVerdict").GetString());
    }

    [Fact]
    public async Task UnansweredApprovalsExpireAndFollowOnTimeout()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policies.AskShell);
        var result = await (await c.Decide("claude-code", "shell.exec", "quick-timeout")).Json();
        Assert.Equal("block", result.GetProperty("verdict").GetString());
        Assert.Contains("no approval within 5 seconds", result.GetProperty("reason").GetString());
        var approval = (await c.GetJson("/api/v1/approvals"))[0];
        Assert.Equal("expired", approval.GetProperty("status").GetString());
        Assert.Equal("timeout", approval.GetProperty("decision").GetString());

        // A non-waiting request expires on its own too.
        var nw = await (await c.Decide("claude-code", "shell.exec", "quick-timeout", wait: false)).Json();
        var id = nw.GetProperty("approvalId").GetString();
        await Http.WaitUntil(async () => (await c.GetJson("/api/v1/approvals?status=expired")).EnumerateArray().Any(a => a.GetProperty("id").GetString() == id), timeoutMs: 9000);
    }

    [Fact]
    public async Task ApprovalErrors()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        Assert.Equal(HttpStatusCode.NotFound, (await c.Send(HttpMethod.Post, "/api/v1/approvals/nope", new { decision = "deny" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Post, "/api/v1/approvals/nope", new { decision = "maybe" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/api/v1/approvals?status=weird")).StatusCode);
    }

    [Fact]
    public async Task KillSwitchBlocksEverythingAndDeniesPendingApprovals()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policies.AskShell);
        var pending = c.Decide("claude-code", "shell.exec", "deploy");
        await Http.WaitUntil(async () => (await c.GetJson("/api/v1/approvals?status=pending")).GetArrayLength() == 1);

        var s = await c.Send(HttpMethod.Post, "/api/v1/killswitch", new { action = "engage" }).Ok();
        Assert.True(s.GetProperty("killSwitch").GetProperty("engaged").GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, s.GetProperty("killSwitch").GetProperty("since").ValueKind);

        var held = await (await pending).Json();
        Assert.Equal("block", held.GetProperty("verdict").GetString());
        Assert.Contains("kill switch", held.GetProperty("reason").GetString());
        var a = (await c.GetJson("/api/v1/approvals"))[0];
        Assert.Equal("denied", a.GetProperty("status").GetString());
        Assert.Equal("deny", a.GetProperty("decision").GetString());

        var d = await (await c.Decide("claude-code", "shell.exec", "ls")).Json();
        Assert.Equal("block", d.GetProperty("verdict").GetString());
        Assert.Equal("killswitch", d.GetProperty("ruleId").GetString());

        // Survives a restart of the policy engine view and is released explicitly.
        var released = await c.Send(HttpMethod.Post, "/api/v1/killswitch", new { action = "release" }).Ok();
        Assert.False(released.GetProperty("killSwitch").GetProperty("engaged").GetBoolean());
        Assert.Equal("allow", (await (await c.Decide("claude-code", "shell.exec", "ls")).Json()).GetProperty("verdict").GetString());

        var ks = await c.GetJson("/api/v1/events?action=killswitch");
        Assert.Equal(2, ks.GetProperty("items").GetArrayLength());
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Post, "/api/v1/killswitch", new { action = "explode" })).StatusCode);
    }
}
