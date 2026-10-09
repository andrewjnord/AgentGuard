using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json;
using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Service.Platform;
using AgentGuard.Service.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace AgentGuard.Service.Tests;

/// <summary>A service instance on an in-memory server with its own data directory, fixed token and no background workers.</summary>
public sealed class ServiceFixture : WebApplicationFactory<Program>
{
    public const string Token = "test-token-0123456789";

    public string Root { get; } = Path.Combine(Path.GetTempPath(), "agentguard-svc-" + Guid.NewGuid().ToString("n"));
    public string DataDir => Path.Combine(Root, "data");
    public string InstallDir => Path.Combine(Root, "install");
    public string ProfileDir => Path.Combine(Root, "profile");

    public IEnforcementAdapters? Adapters { get; init; }
    public IProcessSource? ProcessSource { get; init; }
    public HttpMessageHandler? McpUpstream { get; init; }

    public ServiceFixture()
    {
        Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(InstallDir);
        Directory.CreateDirectory(ProfileDir);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("AgentGuard:DataDir", DataDir);
        builder.UseSetting("AgentGuard:InstallDir", InstallDir);
        builder.UseSetting("AgentGuard:DevMode", "true");
        builder.UseSetting("AgentGuard:Token", Token);
        builder.UseSetting("AgentGuard:DisableWorkers", "true");
        builder.UseSetting("AgentGuard:DisableEnforcement", "true");
        builder.UseSetting("AgentGuard:UserProfiles:0", ProfileDir);
        builder.ConfigureTestServices(services =>
        {
            if (Adapters is not null) services.Replace(ServiceDescriptor.Singleton(Adapters));
            if (ProcessSource is not null) services.Replace(ServiceDescriptor.Singleton(ProcessSource));
            if (McpUpstream is not null)
                services.AddHttpClient(Api.McpForwarder.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => McpUpstream);
            // The tray pipe only runs on Windows; keep it out of tests everywhere.
            var tray = services.FirstOrDefault(d => d.ImplementationType == typeof(Api.TrayPipeServer));
            if (tray is not null) services.Remove(tray);
        });
    }

    public HttpClient Client(bool auth = true)
    {
        var c = CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("http://localhost"), AllowAutoRedirect = false });
        if (auth) c.DefaultRequestHeaders.Add("X-AgentGuard-Token", Token);
        return c;
    }

    public T Get<T>() where T : notnull => Services.GetRequiredService<T>();

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(Root, true); } catch { }
    }
}

public static class Http
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public static async Task<JsonElement> Json(this HttpResponseMessage r)
    {
        var text = await r.Content.ReadAsStringAsync();
        return text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    public static async Task<JsonElement> GetJson(this HttpClient c, string url)
    {
        var r = await c.GetAsync(url);
        Assert.True(r.IsSuccessStatusCode, $"GET {url} -> {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
        return await r.Json();
    }

    public static async Task<HttpResponseMessage> Send(this HttpClient c, HttpMethod m, string url, object? body = null)
    {
        var req = new HttpRequestMessage(m, url);
        if (body is not null) req.Content = JsonContent.Create(body);
        return await c.SendAsync(req);
    }

    public static async Task<JsonElement> Ok(this Task<HttpResponseMessage> call)
    {
        var r = await call;
        Assert.True(r.IsSuccessStatusCode, $"{r.RequestMessage?.Method} {r.RequestMessage?.RequestUri} -> {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
        return await r.Json();
    }

    public static Task<HttpResponseMessage> Decide(this HttpClient c, string agentId, string action, string target, bool? wait = null, string source = "hook", string? userProfile = null, string? cwd = null) =>
        c.Send(HttpMethod.Post, "/api/v1/decide", new { agentId, action, target, source, wait, userProfile, cwd });

    public static async Task<JsonElement> ApplyPolicy(this HttpClient c, string yaml) =>
        await c.Send(HttpMethod.Put, "/api/v1/policy", new { yaml }).Ok();

    public static async Task WaitUntil(Func<Task<bool>> condition, int timeoutMs = 5000)
    {
        var until = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < until)
        {
            if (await condition()) return;
            await Task.Delay(25);
        }
        Assert.Fail("Condition not met in time.");
    }
}

/// <summary>Policies used across tests.</summary>
public static class Policies
{
    public const string AskShell = """
        version: 1
        mode: enforce
        rules:
          - id: block-ssh
            match:
              action: file.read
              path: ["~/.ssh/**"]
            verdict: block
            severity: high
          - id: ask-deploy
            match:
              action: shell.exec
              command_regex: 'deploy'
            verdict: ask
            severity: medium
            timeout_seconds: 30
            on_timeout: block
          - id: ask-quick
            match:
              action: shell.exec
              command_regex: 'quick-timeout'
            verdict: ask
            timeout_seconds: 5
            on_timeout: block
          - id: alert-curl
            match:
              action: shell.exec
              command_regex: 'curl'
            verdict: log
            severity: medium
            alert: true
        """;
}

// ---------------------------------------------------------------------- fakes

public sealed class FakeProcessSource : IProcessSource
{
    public List<ProcessInfo> Processes { get; } = new();
    public IReadOnlyList<ProcessInfo> Snapshot() => Processes.ToList();
}

public sealed class FakeProcessController : IProcessController
{
    private readonly FakeProcessSource _source;
    public ConcurrentDictionary<int, byte> Suspended { get; } = new();
    public ConcurrentDictionary<int, byte> Terminated { get; } = new();
    public HashSet<int> OsProtected { get; } = new();

    public FakeProcessController(FakeProcessSource source) => _source = source;

    public bool IsProtectedByOs(int pid) => OsProtected.Contains(pid);

    public ProcessTarget? Live(int pid) =>
        _source.Processes.FirstOrDefault(p => p.Pid == pid && !Terminated.ContainsKey(pid)) is { } p ? new ProcessTarget(p.Pid, p.StartTime, p.Name, p.ExePath) : null;

    public bool Suspend(ProcessTarget p) => Suspended.TryAdd(p.Pid, 0);
    public bool Resume(ProcessTarget p) => Suspended.TryRemove(p.Pid, out _);
    public bool Terminate(ProcessTarget p) => Terminated.TryAdd(p.Pid, 0);
}

public sealed class FakeNetworkBlocker : INetworkBlocker
{
    public ConcurrentDictionary<string, IReadOnlyCollection<string>> Rules { get; } = new();
    public void Block(string agentId, IReadOnlyCollection<string> programPaths) => Rules[agentId] = programPaths;
    public void Unblock(string agentId) => Rules.TryRemove(agentId, out _);
    public IReadOnlyCollection<string> BlockedAgents() => Rules.Keys.ToList();
}

public sealed class FakeAdapters : IEnforcementAdapters
{
    public FakeAdapters(FakeProcessSource source)
    {
        Controller = new FakeProcessController(source);
        Blocker = new FakeNetworkBlocker();
    }

    public FakeProcessController Controller { get; }
    public FakeNetworkBlocker Blocker { get; }
    public IProcessController? Processes => Controller;
    public INetworkBlocker? Network => Blocker;
    public Func<ITelemetrySource>? TelemetryFactory => null;
    public IFileTrust? FileTrust => null;
}

/// <summary>Records upstream MCP requests and answers each with a canned JSON-RPC result.</summary>
public sealed class FakeMcpUpstream : HttpMessageHandler
{
    public ConcurrentQueue<(string Method, string Url, string Body, Dictionary<string, string> Headers)> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        Requests.Enqueue((request.Method.Method, request.RequestUri!.ToString(), body, request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value))));
        var id = JsonDocument.Parse(body.Length > 0 ? body : "{}").RootElement.TryGetProperty("id", out var i) ? i.GetRawText() : "null";
        var resp = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent($$$"""{"jsonrpc":"2.0","id":{{{id}}},"result":{"content":[{"type":"text","text":"upstream ok"}]}}""", System.Text.Encoding.UTF8, "application/json"),
        };
        resp.Headers.Add("Mcp-Session-Id", "sess-1");
        return resp;
    }
}
