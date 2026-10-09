using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace AgentGuard.Service.Tests;

public class EventsAndAlertsTests
{
    [Fact]
    public async Task PagesNewestFirstWithACursor()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        for (var i = 0; i < 7; i++) await c.Decide("claude-code", "shell.exec", $"echo {i}");
        var all = new List<long>();
        long? before = null;
        do
        {
            var page = await c.GetJson($"/api/v1/events?agentId=claude-code&limit=3{(before is null ? "" : $"&before={before}")}");
            var items = page.GetProperty("items").EnumerateArray().Select(e => e.GetProperty("id").GetInt64()).ToList();
            all.AddRange(items);
            before = page.GetProperty("nextBefore").ValueKind == JsonValueKind.Null ? null : page.GetProperty("nextBefore").GetInt64();
        } while (before is not null);
        Assert.Equal(7, all.Count);
        Assert.Equal(all.OrderByDescending(x => x), all);
    }

    [Fact]
    public async Task FiltersAndValidation()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.Decide("claude-code", "shell.exec", "npm run build");
        await c.Decide("claude-code", "file.read", "/home/u/.ssh/config", userProfile: "/home/u");
        await c.Decide("cursor", "shell.exec", "git status");

        Assert.Single((await c.GetJson("/api/v1/events?verdict=block")).GetProperty("items").EnumerateArray());
        Assert.Single((await c.GetJson("/api/v1/events?agentId=cursor")).GetProperty("items").EnumerateArray());
        Assert.Single((await c.GetJson("/api/v1/events?q=npm%20run")).GetProperty("items").EnumerateArray());
        Assert.Equal(2, (await c.GetJson("/api/v1/events?action=shell.exec")).GetProperty("items").GetArrayLength());
        Assert.Single((await c.GetJson("/api/v1/events?severity=high")).GetProperty("items").EnumerateArray());
        Assert.Equal(3, (await c.GetJson("/api/v1/events?source=hook")).GetProperty("items").GetArrayLength());
        var future = DateTimeOffset.UtcNow.AddHours(1).ToString("O");
        Assert.Empty((await c.GetJson($"/api/v1/events?from={Uri.EscapeDataString(future)}")).GetProperty("items").EnumerateArray());

        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/api/v1/events?verdict=maybe")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/api/v1/events?from=yesterday")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/api/v1/events?limit=0")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/api/v1/events/999999")).StatusCode);
    }

    [Fact]
    public async Task AlertsAreRaisedAndCanBeAcknowledged()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policies.AskShell);
        await c.Decide("claude-code", "shell.exec", "curl https://example.com");
        var alerts = await c.GetJson("/api/v1/alerts?status=open");
        var alert = Assert.Single(alerts.EnumerateArray());
        Assert.Equal("alert-curl", alert.GetProperty("ruleId").GetString());
        Assert.Equal("medium", alert.GetProperty("severity").GetString());
        Assert.StartsWith("Flagged: claude-code tried to run curl", alert.GetProperty("title").GetString());

        var id = alert.GetProperty("id").GetInt64();
        var acked = await c.Send(HttpMethod.Put, $"/api/v1/alerts/{id}", new { status = "acked" }).Ok();
        Assert.Equal("acked", acked.GetProperty("status").GetString());
        Assert.Empty((await c.GetJson("/api/v1/alerts?status=open")).EnumerateArray());
        Assert.Equal(0, (await c.GetJson("/api/v1/status")).GetProperty("counts").GetProperty("openAlerts").GetInt32());

        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Put, $"/api/v1/alerts/{id}", new { status = "gone" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await c.Send(HttpMethod.Put, "/api/v1/alerts/424242", new { status = "closed" })).StatusCode);
    }
}

public class PolicyApiTests
{
    [Fact]
    public async Task ValidateReportsLineNumbers()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var v = await c.Send(HttpMethod.Post, "/api/v1/policy/validate", new { yaml = "version: 1\nmode: enforce\nrules:\n  - id: x\n    verdict: perhaps\n" }).Ok();
        Assert.False(v.GetProperty("ok").GetBoolean());
        var err = v.GetProperty("errors")[0];
        Assert.Equal(5, err.GetProperty("line").GetInt32());
        Assert.False(string.IsNullOrEmpty(err.GetProperty("message").GetString()));

        var good = await c.Send(HttpMethod.Post, "/api/v1/policy/validate", new { yaml = Policies.AskShell }).Ok();
        Assert.True(good.GetProperty("ok").GetBoolean());
        Assert.Equal(4, good.GetProperty("ruleCount").GetInt32());
    }

    [Fact]
    public async Task ApplyRejectsInvalidAndVersionsValid()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var start = await c.GetJson("/api/v1/policy");
        Assert.Equal("enforce", start.GetProperty("mode").GetString());

        var bad = await c.Send(HttpMethod.Put, "/api/v1/policy", new { yaml = "rules: [" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        var body = await bad.Json();
        Assert.False(body.GetProperty("ok").GetBoolean());
        Assert.True(body.GetProperty("errors").GetArrayLength() > 0);
        Assert.Equal(start.GetProperty("version").GetInt32(), (await c.GetJson("/api/v1/policy")).GetProperty("version").GetInt32());

        var applied = await c.ApplyPolicy(Policies.AskShell);
        Assert.Equal(start.GetProperty("version").GetInt32() + 1, applied.GetProperty("version").GetInt32());
        Assert.Equal(4, applied.GetProperty("ruleCount").GetInt32());
        Assert.Equal(Policies.AskShell, File.ReadAllText(Path.Combine(f.DataDir, "policy.yaml")));

        var history = await c.GetJson("/api/v1/policy/history");
        Assert.Equal(2, history.GetArrayLength());
        var old = await c.GetJson($"/api/v1/policy/history/{start.GetProperty("version").GetInt32()}");
        Assert.Equal(start.GetProperty("yaml").GetString(), old.GetProperty("yaml").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await c.GetAsync("/api/v1/policy/history/999")).StatusCode);

        Assert.Single((await c.GetJson("/api/v1/events?action=policy.changed")).GetProperty("items").EnumerateArray());
    }
}

public class SettingsApiTests
{
    [Fact]
    public async Task SecretsAreMaskedAndKept()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var s = await c.GetJson("/api/v1/settings");
        Assert.Equal(JsonValueKind.Null, s.GetProperty("exports").GetProperty("splunk").GetProperty("token").ValueKind);
        Assert.Equal("closed", s.GetProperty("failMode").GetString());

        var edited = JsonSerializer.Deserialize<Dictionary<string, object?>>(s.GetRawText())!;
        var json = s.GetRawText().Replace("\"token\":null", "\"token\":\"hec-secret\"").Replace("\"failMode\":\"closed\"", "\"failMode\":\"open\"");
        var saved = await (await c.PutAsync("/api/v1/settings", new StringContent(json, System.Text.Encoding.UTF8, "application/json"))).Json();
        Assert.Equal("********", saved.GetProperty("exports").GetProperty("splunk").GetProperty("token").GetString());
        Assert.Equal("open", saved.GetProperty("failMode").GetString());

        // Sending the mask back keeps the stored secret.
        var r = await c.PutAsync("/api/v1/settings", new StringContent(saved.GetRawText().Replace("\"retentionDays\":30", "\"retentionDays\":45"), System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("hec-secret", f.Get<Services.SettingsManager>().Current.Exports.Splunk.Token);
        Assert.Equal(45, f.Get<Services.SettingsManager>().Current.RetentionDays);

        // The published client config follows the fail mode.
        Assert.True(Core.Integration.ClientConfig.Load(Path.Combine(f.DataDir, "public", "client.json")).FailOpen);
    }

    [Fact]
    public async Task InvalidSettingsAreRejected()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var s = await c.GetJson("/api/v1/settings");
        var r = await c.PutAsync("/api/v1/settings", new StringContent(s.GetRawText().Replace("\"retentionDays\":30", "\"retentionDays\":0"), System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("retentionDays", (await r.Json()).GetProperty("error").GetString());
    }

    [Fact]
    public async Task TestExportWritesToTheJsonDirectory()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        var dir = Path.Combine(f.Root, "siem");
        var s = await c.GetJson("/api/v1/settings");
        var json = s.GetRawText().Replace("\"jsonFile\":{\"enabled\":false,\"directory\":\"\"}", $"\"jsonFile\":{{\"enabled\":true,\"directory\":{JsonSerializer.Serialize(dir)}}}");
        Assert.Equal(HttpStatusCode.OK, (await c.PutAsync("/api/v1/settings", new StringContent(json, System.Text.Encoding.UTF8, "application/json"))).StatusCode);

        var result = await c.Send(HttpMethod.Post, "/api/v1/settings/test-export", new { target = "jsonFile" }).Ok();
        Assert.True(result.GetProperty("ok").GetBoolean(), result.GetRawText());
        var file = Assert.Single(Directory.GetFiles(dir));
        Assert.Contains("AgentGuard export test", File.ReadAllText(file));

        var splunk = await c.Send(HttpMethod.Post, "/api/v1/settings/test-export", new { target = "splunk" }).Ok();
        Assert.False(splunk.GetProperty("ok").GetBoolean()); // example.com HEC is not reachable from tests
        Assert.Equal(HttpStatusCode.BadRequest, (await c.Send(HttpMethod.Post, "/api/v1/settings/test-export", new { target = "fax" })).StatusCode);
    }
}

public class IntegrityAndExportTests
{
    [Fact]
    public async Task VerifyDetectsTampering()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        for (var i = 0; i < 5; i++) await c.Decide("claude-code", "shell.exec", $"echo {i}");
        var ok = await c.Send(HttpMethod.Post, "/api/v1/integrity/verify").Ok();
        Assert.True(ok.GetProperty("ok").GetBoolean());
        Assert.True(ok.GetProperty("checked").GetInt32() >= 5);
        Assert.True((await c.GetJson("/api/v1/status")).GetProperty("integrity").GetProperty("ok").GetBoolean());

        var victim = (await c.GetJson("/api/v1/events?q=echo%202")).GetProperty("items")[0].GetProperty("id").GetInt64();
        using (var db = new SqliteConnection($"Data Source={Path.Combine(f.DataDir, "agentguard.db")};Pooling=false"))
        {
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "UPDATE events SET target='echo innocent' WHERE id=$id";
            cmd.Parameters.AddWithValue("$id", victim);
            Assert.Equal(1, cmd.ExecuteNonQuery());
        }
        var bad = await c.Send(HttpMethod.Post, "/api/v1/integrity/verify").Ok();
        Assert.False(bad.GetProperty("ok").GetBoolean());
        Assert.Equal(victim, bad.GetProperty("firstBadId").GetInt64());
        Assert.False((await c.GetJson("/api/v1/status")).GetProperty("integrity").GetProperty("ok").GetBoolean());
        var alert = (await c.GetJson("/api/v1/alerts?status=open")).EnumerateArray().Single();
        Assert.Equal("critical", alert.GetProperty("severity").GetString());
    }

    [Fact]
    public async Task ExportsOcsfCefAndJson()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.Decide("claude-code", "shell.exec", "npm test");
        await c.Decide("claude-code", "file.read", "/home/u/.ssh/id_rsa", userProfile: "/home/u");
        await c.Decide("cursor", "shell.exec", "ls");

        var ocsf = await c.GetAsync("/api/v1/export?format=ocsf&agentId=claude-code");
        Assert.Equal("application/x-ndjson", ocsf.Content.Headers.ContentType?.MediaType);
        Assert.Contains("attachment", ocsf.Content.Headers.ContentDisposition?.ToString() ?? ocsf.Headers.GetValues("Content-Disposition").First());
        var lines = (await ocsf.Content.ReadAsStringAsync()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        foreach (var l in lines) Assert.True(JsonDocument.Parse(l).RootElement.TryGetProperty("class_uid", out _));

        var cef = await (await c.GetAsync("/api/v1/export?format=cef")).Content.ReadAsStringAsync();
        Assert.All(cef.Split('\n', StringSplitOptions.RemoveEmptyEntries), l => Assert.StartsWith("CEF:0|AgentGuard|AgentGuard|", l));

        var anon = f.Client(auth: false);
        var json = await anon.GetAsync($"/api/v1/export?format=json&token={ServiceFixture.Token}");
        Assert.Equal(HttpStatusCode.OK, json.StatusCode);
        var first = JsonDocument.Parse((await json.Content.ReadAsStringAsync()).Split('\n')[0]).RootElement;
        Assert.EndsWith("Z", first.GetProperty("ts").GetString());

        Assert.Equal(HttpStatusCode.BadRequest, (await c.GetAsync("/api/v1/export?format=pdf")).StatusCode);
        Assert.NotEmpty((await c.GetJson("/api/v1/events?q=Exported")).GetProperty("items").EnumerateArray());
    }
}

public class StreamTests
{
    [Fact]
    public async Task StreamsHelloThenLiveEvents()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var resp = await c.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/api/v1/stream"), HttpCompletionOption.ResponseHeadersRead, cts.Token);
        Assert.Equal("text/event-stream", resp.Content.Headers.ContentType?.MediaType);
        using var reader = new StreamReader(await resp.Content.ReadAsStreamAsync(cts.Token));

        async Task<(string Name, JsonElement Data)> Next()
        {
            string? name = null;
            while (true)
            {
                var line = await reader.ReadLineAsync(cts.Token);
                if (line is null) throw new EndOfStreamException();
                if (line.StartsWith("event: ")) name = line[7..];
                else if (line.StartsWith("data: ")) return (name!, JsonDocument.Parse(line[6..]).RootElement.Clone());
            }
        }

        var hello = await Next();
        Assert.Equal("hello", hello.Name);
        Assert.Equal("enforce", hello.Data.GetProperty("mode").GetString());

        await c.Decide("claude-code", "file.read", "/home/u/.ssh/id_rsa", userProfile: "/home/u");
        var seen = new List<string>();
        while (seen.Count < 6)
        {
            var (name, data) = await Next();
            seen.Add(name);
            if (name == "event")
            {
                Assert.Equal("file.read", data.GetProperty("action").GetString());
                Assert.False(data.TryGetProperty("prevHash", out _));
                break;
            }
        }
        Assert.Contains("agent", seen); // the agent was registered on first contact
        Assert.Contains("event", seen);
    }
}
