using System.Net;
using System.Text.Json;
using AgentGuard.Core;
using AgentGuard.Core.Export;
using AgentGuard.Core.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace AgentGuard.Core.Tests;

public sealed class TempDir : IDisposable
{
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "agentguard-tests-" + Guid.NewGuid().ToString("n"));
    public TempDir() => Directory.CreateDirectory(Path);
    public string File(string name) => System.IO.Path.Combine(Path, name);
    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(Path, true); } catch { }
    }
}

public class EventStoreTests
{
    private static AgentEvent Sample(int i, DateTimeOffset? ts = null) => new()
    {
        Ts = ts ?? DateTimeOffset.UtcNow,
        AgentId = "claude-code",
        AgentName = "Claude Code",
        Pid = 1000 + i,
        Action = i % 3 == 0 ? Actions.FileRead : Actions.ShellExec,
        Target = i % 3 == 0 ? $"C:/Users/ana/file{i}.txt" : $"npm run task{i}",
        Details = new() { ["tool"] = "Bash", ["n"] = (long)i, ["nested"] = new Dictionary<string, object?> { ["a"] = "b" } },
        Verdict = i % 5 == 0 ? Verdict.Block : Verdict.Log,
        RuleId = i % 5 == 0 ? "protect-ssh-keys" : null,
        Severity = i % 5 == 0 ? Severity.High : Severity.Info,
        Source = EventSources.Hook,
        Enforced = i % 5 == 0,
    };

    [Fact]
    public async Task AppendsAndChainsAndVerifies()
    {
        using var dir = new TempDir();
        using var store = new EventStore(dir.File("db.sqlite"));
        AgentEvent? prev = null;
        for (var i = 1; i <= 50; i++)
        {
            var e = await store.AppendAsync(Sample(i));
            Assert.Equal(i, e.Id);
            Assert.Equal(prev?.Hash ?? EventStore.GenesisHash, e.PrevHash);
            prev = e;
        }
        var result = store.VerifyIntegrity();
        Assert.True(result.Ok);
        Assert.Equal(50, result.Checked);

        var back = store.GetEvent(10)!;
        Assert.Equal(Verdict.Block, back.Verdict);
        Assert.Equal(10L, Assert.IsType<long>(back.Details["n"]));
        Assert.Equal("b", ((Dictionary<string, object?>)back.Details["nested"]!)["a"]);
    }

    [Fact]
    public async Task DetectsTamperingAndDeletion()
    {
        using var dir = new TempDir();
        var path = dir.File("db.sqlite");
        using (var store = new EventStore(path))
            for (var i = 1; i <= 20; i++) await store.AppendAsync(Sample(i));

        using (var c = new SqliteConnection($"Data Source={path}"))
        {
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "UPDATE events SET verdict='allow' WHERE id=7";
            cmd.ExecuteNonQuery();
        }
        using (var store = new EventStore(path))
        {
            var r = store.VerifyIntegrity();
            Assert.False(r.Ok);
            Assert.Equal(7, r.FirstBadId);
        }

        using (var c = new SqliteConnection($"Data Source={path}"))
        {
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "UPDATE events SET verdict='log' WHERE id=7; DELETE FROM events WHERE id=12";
            cmd.ExecuteNonQuery();
        }
        using (var store = new EventStore(path))
        {
            var r = store.VerifyIntegrity();
            Assert.False(r.Ok);
            Assert.Equal(13, r.FirstBadId);
        }
    }

    [Fact]
    public async Task PruneKeepsChainVerifiable()
    {
        using var dir = new TempDir();
        using var store = new EventStore(dir.File("db.sqlite"));
        var old = DateTimeOffset.UtcNow.AddDays(-40);
        for (var i = 1; i <= 10; i++) await store.AppendAsync(Sample(i, old.AddMinutes(i)));
        for (var i = 11; i <= 15; i++) await store.AppendAsync(Sample(i));
        var removed = await store.PruneAsync(DateTimeOffset.UtcNow.AddDays(-30));
        Assert.Equal(10, removed);
        var r = store.VerifyIntegrity();
        Assert.True(r.Ok);
        Assert.Equal(5, r.Checked);
        var next = await store.AppendAsync(Sample(16));
        Assert.Equal(16, next.Id);
        Assert.True(store.VerifyIntegrity().Ok);
    }

    [Fact]
    public async Task QueriesFilterAndPage()
    {
        using var dir = new TempDir();
        using var store = new EventStore(dir.File("db.sqlite"));
        for (var i = 1; i <= 30; i++) await store.AppendAsync(Sample(i));
        var blocked = store.QueryEvents(new EventFilter { Verdict = Verdict.Block });
        Assert.Equal(6, blocked.Count);
        Assert.True(blocked[0].Id > blocked[1].Id);
        var page = store.QueryEvents(new EventFilter { Limit = 10 });
        var next = store.QueryEvents(new EventFilter { Limit = 10, Before = page[^1].Id });
        Assert.Equal(page[^1].Id - 1, next[0].Id);
        Assert.Single(store.QueryEvents(new EventFilter { Query = "file12.txt" }));
        Assert.Equal(10, store.QueryEvents(new EventFilter { Action = "file.*" }).Count);
        Assert.Empty(store.QueryEvents(new EventFilter { Query = "100%_" }));

        var counts = store.CountsSince(DateTimeOffset.UtcNow.AddHours(-1));
        Assert.Equal(30, counts.Events);
        Assert.Equal(6, counts.Blocked);
        var buckets = store.Activity(DateTimeOffset.UtcNow, 24);
        Assert.Equal(24, buckets.Count);
        Assert.Equal(30, buckets[^1].Total);
    }

    [Fact]
    public void AgentsAlertsApprovalsPoliciesSettings()
    {
        using var dir = new TempDir();
        using var store = new EventStore(dir.File("db.sqlite"));
        store.UpsertAgent(new AgentRecord { Id = "cursor", Name = "Cursor", Kind = AgentKinds.Desktop, ExePath = "C:/c.exe" });
        store.UpsertAgent(new AgentRecord { Id = "cursor", Name = "Cursor", Kind = AgentKinds.Desktop, Trust = "allowed" });
        var a = Assert.Single(store.ListAgents());
        Assert.Equal("allowed", a.Trust);
        Assert.Equal("C:/c.exe", a.ExePath);

        var alert = store.AddAlert(new AlertRecord { EventId = 1, Ts = DateTimeOffset.UtcNow, Severity = Severity.High, Title = "t", AgentId = "x", AgentName = "X", Action = "file.read", Target = "/x" });
        Assert.Equal(1, store.CountAlerts("open"));
        Assert.Equal("acked", store.SetAlertStatus(alert.Id, "acked")!.Status);

        var ap = new ApprovalRecord { EventId = 3, AgentId = "x", Action = "shell.exec", Target = "rm -rf /", ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1) };
        store.SaveApproval(ap);
        ap.Status = "allowed";
        store.SaveApproval(ap);
        Assert.Empty(store.ListApprovals("pending"));
        Assert.Equal("allowed", store.GetApproval(ap.Id)!.Status);

        store.SavePolicy("version: 1", "ana", 0);
        var v2 = store.SavePolicy("version: 1\nmode: monitor", "ana", 0);
        Assert.Equal(2, v2.Version);
        Assert.Equal("version: 1", store.GetPolicy(1)!.Yaml);
        Assert.Equal(2, store.PolicyHistory().Count);

        Assert.True(store.RecordHostContact("x", "GitHub.com"));
        Assert.False(store.RecordHostContact("x", "github.com"));
        Assert.True(store.HasHostContact("x", "github.com"));

        store.SetSetting("k", "v");
        Assert.Equal("v", store.GetSetting("k"));
    }
}

public class ExportTests
{
    private static AgentEvent Blocked() => new()
    {
        Id = 42,
        Ts = DateTimeOffset.FromUnixTimeMilliseconds(1_760_000_000_000),
        AgentId = "claude-code",
        AgentName = "Claude Code",
        Pid = 4242,
        Action = Actions.FileRead,
        Target = @"C:\Users\ana\.ssh\id_ed25519",
        Verdict = Verdict.Block,
        RuleId = "protect-ssh-keys",
        Severity = Severity.High,
        Source = EventSources.Hook,
        Enforced = true,
        Hash = "abc",
    };

    [Fact]
    public void OcsfFileActivity()
    {
        var o = OcsfMapper.Map(Blocked(), "WS-1", "0.1.0");
        Assert.Equal(1001, (int)o["class_uid"]!);
        Assert.Equal(100102, (int)o["type_uid"]!);
        Assert.Equal(2, (int)o["disposition_id"]!);
        Assert.Equal(4, (int)o["severity_id"]!);
        Assert.Equal("id_ed25519", (string)o["file"]!["name"]!);
        Assert.Equal("protect-ssh-keys", (string)o["unmapped"]!["agentguard"]!["rule_id"]!);
        Assert.Equal(1_760_000_000_000L, (long)o["time"]!);
    }

    [Fact]
    public void OcsfNetworkAndApi()
    {
        var e = Blocked();
        e.Action = Actions.NetConnect;
        e.Target = "140.82.112.3:443";
        e.Details = new() { ["hostname"] = "github.com", ["ip"] = "140.82.112.3", ["port"] = 443L };
        var o = OcsfMapper.Map(e, "WS-1", "0.1.0");
        Assert.Equal(4001, (int)o["class_uid"]!);
        Assert.Equal("github.com", (string)o["dst_endpoint"]!["hostname"]!);
        Assert.Equal(443L, (long)o["dst_endpoint"]!["port"]!);

        e.Action = Actions.McpCall;
        e.Target = "github/create_issue";
        o = OcsfMapper.Map(e, "WS-1", "0.1.0");
        Assert.Equal(6003, (int)o["class_uid"]!);
        Assert.Equal("create_issue", (string)o["api"]!["operation"]!);
    }

    [Fact]
    public void CefEscapes()
    {
        var e = Blocked();
        e.Target = "echo a=b | c\\d";
        e.Action = Actions.ShellExec;
        var cef = Cef.Format(e, "WS-1", "0.1.0");
        Assert.StartsWith("CEF:0|AgentGuard|AgentGuard|0.1.0|shell.exec|", cef);
        Assert.Contains("msg=echo a\\=b | c\\\\d", cef);
        Assert.Contains("|8|", cef);
        Assert.Contains("cs2=protect-ssh-keys", cef);
        var syslog = new SyslogExporter(new SyslogSettings(), "WS-1", "0.1.0").Frame(e);
        Assert.StartsWith("<107>1 ", syslog);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request;
        public string? Body;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Request = request;
            Body = await request.Content!.ReadAsStringAsync(ct);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"text\":\"Success\",\"code\":0}") };
        }
    }

    [Fact]
    public async Task SplunkHecSendsOcsfWithToken()
    {
        var handler = new CaptureHandler();
        var exporter = new SplunkHecExporter(new SplunkSettings { Enabled = true, Url = "https://splunk:8088/services/collector/event", Token = "t0k", Index = "agents" }, "WS-1", "0.1.0", handler);
        await exporter.ExportAsync(new[] { Blocked(), Blocked() }, CancellationToken.None);
        Assert.Equal("Splunk t0k", handler.Request!.Headers.Authorization!.ToString());
        var lines = handler.Body!.Trim().Split('\n');
        Assert.Equal(2, lines.Length);
        var doc = JsonDocument.Parse(lines[0]).RootElement;
        Assert.Equal("agents", doc.GetProperty("index").GetString());
        Assert.Equal(1001, doc.GetProperty("event").GetProperty("class_uid").GetInt32());
    }

    [Fact]
    public async Task JsonFileWritesDailyNdjson()
    {
        using var dir = new TempDir();
        await new JsonFileExporter(dir.Path, "WS-1", "0.1.0").ExportAsync(new[] { Blocked() }, CancellationToken.None);
        var file = Assert.Single(Directory.GetFiles(dir.Path));
        Assert.EndsWith(".ocsf.ndjson", file);
        Assert.Equal(1001, JsonDocument.Parse(File.ReadAllLines(file)[0]).RootElement.GetProperty("class_uid").GetInt32());
    }

    [Fact]
    public async Task SyslogUdpDelivers()
    {
        using var listener = new System.Net.Sockets.UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;
        var exporter = new SyslogExporter(new SyslogSettings { Enabled = true, Host = "127.0.0.1", Port = port, Protocol = "udp" }, "WS-1", "0.1.0");
        var receive = listener.ReceiveAsync();
        await exporter.ExportAsync(new[] { Blocked() }, CancellationToken.None);
        var got = await receive.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Contains("CEF:0|AgentGuard", System.Text.Encoding.UTF8.GetString(got.Buffer));
    }

    [Fact]
    public void RedactorRemovesSecrets()
    {
        var r = new Redactor(new AgentGuardSettings().Redaction.Patterns);
        Assert.DoesNotContain("hunter2", r.Redact("mysql --password=hunter2 db"));
        Assert.DoesNotContain("sk-ant-abcdefghijklmnopqrstu", r.Redact("export KEY=sk-ant-abcdefghijklmnopqrstu"));
        var d = r.Redact(new Dictionary<string, object?> { ["token"] = "abc", ["args"] = new List<object?> { "Bearer xyz.abc" }, ["n"] = 1L });
        Assert.Equal(Redactor.Replacement, d["token"]);
        Assert.Equal(Redactor.Replacement, ((List<object?>)d["args"]!)[0]);
        Assert.Equal(1L, d["n"]);
    }

    [Fact]
    public void SettingsMaskingAndValidation()
    {
        var s = new AgentGuardSettings();
        s.Exports.Splunk.Token = "secret";
        Assert.Equal(AgentGuardSettings.MaskedSecret, s.Masked().Exports.Splunk.Token);
        Assert.Equal("secret", s.Exports.Splunk.Token);
        s.RetentionDays = 0;
        s.Redaction.Patterns.Add("(");
        Assert.Equal(2, s.Validate().Count());
    }
}
