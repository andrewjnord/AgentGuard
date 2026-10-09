using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core.Integration;
using AgentGuard.McpProxy;
using AgentGuard.Service.Tests;

namespace AgentGuard.Tools.Tests;

/// <summary>Runs a <see cref="ProxySession"/> between an in-memory client, a fake MCP server and the in-memory AgentGuard service.</summary>
public sealed class ProxyHarness : IAsyncDisposable
{
    private readonly Pipe _clientToProxy = new();
    private readonly Pipe _proxyToClient = new();
    private readonly Pipe _proxyToServer = new();
    private readonly Pipe _serverToProxy = new();
    private readonly StreamReader _clientReader;
    private readonly Stream _clientWriter;
    private readonly Task _server;
    private readonly AgentGuardClient _api;

    public Task Session { get; }
    public ProxySession Proxy { get; }
    public List<JsonObject> ServerReceived { get; } = new();
    public StringWriter Log { get; } = new();

    public ProxyHarness(ServiceFixture f, string serverName = "fs", bool failOpen = false, McpGate.Decider? decider = null)
    {
        _api = new AgentGuardClient("http://localhost/", handler: f.Server.CreateHandler(), timeout: Timeout.InfiniteTimeSpan);
        var gate = new McpGate(serverName, decider ?? _api.DecideAsync, failOpen) { UserProfile = "/home/u", Cwd = "/repo", Pid = 4242 };
        Proxy = new ProxySession(_clientToProxy.Reader.AsStream(), _proxyToClient.Writer.AsStream(), _proxyToServer.Writer.AsStream(), _serverToProxy.Reader.AsStream(), gate, Log);
        _clientReader = new StreamReader(_proxyToClient.Reader.AsStream(), Encoding.UTF8);
        _clientWriter = _clientToProxy.Writer.AsStream();
        _server = Task.Run(FakeServerAsync);
        Session = Proxy.RunAsync();
    }

    /// <summary>Answers every request with its method name, like a minimal MCP server.</summary>
    private async Task FakeServerAsync()
    {
        using var reader = new StreamReader(_proxyToServer.Reader.AsStream(), Encoding.UTF8);
        var output = _serverToProxy.Writer.AsStream();
        while (await reader.ReadLineAsync() is { } line)
        {
            var msg = JsonNode.Parse(line)!.AsObject();
            lock (ServerReceived) ServerReceived.Add(msg);
            if (msg["id"] is null) continue;
            var reply = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = msg["id"]!.DeepClone(), ["result"] = new JsonObject { ["served"] = msg["method"]!.GetValue<string>() } };
            await output.WriteAsync(Encoding.UTF8.GetBytes(reply.ToJsonString() + "\n"));
            await output.FlushAsync();
        }
        output.Close(); // the server exits when its stdin closes
    }

    public async Task Send(object message)
    {
        await _clientWriter.WriteAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message) + "\n"));
        await _clientWriter.FlushAsync();
    }

    public async Task<JsonObject> Receive(int timeoutMs = 10_000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        var line = await _clientReader.ReadLineAsync(cts.Token) ?? throw new EndOfStreamException();
        return JsonNode.Parse(line)!.AsObject();
    }

    public async Task CloseClient() => await _clientToProxy.Writer.CompleteAsync();

    public async ValueTask DisposeAsync()
    {
        await _clientToProxy.Writer.CompleteAsync();
        try { await Session.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
        _api.Dispose();
    }

    public static object ToolCall(int id, string name, object? arguments = null) =>
        new { jsonrpc = "2.0", id, method = "tools/call", @params = new { name, arguments = arguments ?? new { } } };
}

public class McpProxyTests
{
    private const string Policy = """
        version: 1
        mode: enforce
        rules:
          - id: no-ssh
            match:
              action: file.read
              path: ["~/.ssh/**"]
            verdict: block
            severity: high
          - id: no-drop
            match:
              action: mcp.call
              tool: ["drop_*"]
            verdict: block
          - id: ask-push
            match:
              action: mcp.call
              tool: ["push"]
            verdict: ask
            timeout_seconds: 30
        """;

    [Fact]
    public async Task AllowedCallsReachTheServerAndRepliesComeBack()
    {
        using var f = new ServiceFixture();
        await f.Client().ApplyPolicy(Policy);
        await using var h = new ProxyHarness(f);

        await h.Send(new { jsonrpc = "2.0", id = 1, method = "initialize", @params = new { clientInfo = new { name = "Claude Desktop" } } });
        Assert.Equal("initialize", (await h.Receive())["result"]!["served"]!.GetValue<string>());

        await h.Send(ProxyHarness.ToolCall(2, "read_file", new { path = "/repo/README.md" }));
        var r = await h.Receive();
        Assert.Equal(2, r["id"]!.GetValue<int>());
        Assert.Equal("tools/call", r["result"]!["served"]!.GetValue<string>());

        var events = await f.Client().GetJson("/api/v1/events?agentId=mcp:fs");
        var items = events.GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(items, e => e.GetProperty("action").GetString() == "mcp.call" && e.GetProperty("target").GetString() == "fs/read_file");
        Assert.Contains(items, e => e.GetProperty("action").GetString() == "file.read" && e.GetProperty("target").GetString() == "/repo/README.md");
        Assert.All(items, e => Assert.Equal(4242, e.GetProperty("pid").GetInt32()));
    }

    [Fact]
    public async Task BlockedCallsNeverReachTheServer()
    {
        using var f = new ServiceFixture();
        await f.Client().ApplyPolicy(Policy);
        await using var h = new ProxyHarness(f);

        await h.Send(ProxyHarness.ToolCall(7, "drop_table", new { table = "users" }));
        var r = await h.Receive();
        Assert.Equal(7, r["id"]!.GetValue<int>());
        Assert.True(r["result"]!["isError"]!.GetValue<bool>());

        await h.Send(ProxyHarness.ToolCall(8, "read_file", new { path = "~/.ssh/id_ed25519" }));
        Assert.True((await h.Receive())["result"]!["isError"]!.GetValue<bool>());

        await h.CloseClient();
        await h.Session.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.DoesNotContain(h.ServerReceived, m => m["method"]?.GetValue<string>() == "tools/call");
        Assert.Equal(2, h.Proxy.Blocked);
        Assert.Contains("blocked drop_table", h.Log.ToString());
    }

    [Fact]
    public async Task ACallWaitingForApprovalDoesNotHoldUpOtherTraffic()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policy);
        await using var h = new ProxyHarness(f);

        await h.Send(ProxyHarness.ToolCall(10, "push"));
        string approvalId = "";
        await Http.WaitUntil(async () =>
        {
            var list = await c.GetJson("/api/v1/approvals?status=pending");
            if (list.GetArrayLength() == 0) return false;
            approvalId = list[0].GetProperty("id").GetString()!;
            return true;
        });

        await h.Send(new { jsonrpc = "2.0", id = 11, method = "ping" });
        var ping = await h.Receive();
        Assert.Equal(11, ping["id"]!.GetValue<int>()); // answered while call 10 waits

        await c.Send(HttpMethod.Post, $"/api/v1/approvals/{approvalId}", new { decision = "allow_once" }).Ok();
        var pushed = await h.Receive();
        Assert.Equal(10, pushed["id"]!.GetValue<int>());
        Assert.Equal("tools/call", pushed["result"]!["served"]!.GetValue<string>());
    }

    [Fact]
    public async Task CancellingACallThatIsBeingCheckedDropsIt()
    {
        using var f = new ServiceFixture();
        var c = f.Client();
        await c.ApplyPolicy(Policy);
        await using var h = new ProxyHarness(f);

        await h.Send(ProxyHarness.ToolCall(20, "push"));
        await Http.WaitUntil(async () => (await c.GetJson("/api/v1/approvals?status=pending")).GetArrayLength() == 1);
        await h.Send(new { jsonrpc = "2.0", method = "notifications/cancelled", @params = new { requestId = 20, reason = "user" } });
        await h.Send(new { jsonrpc = "2.0", id = 21, method = "ping" });
        Assert.Equal(21, (await h.Receive())["id"]!.GetValue<int>());

        await h.CloseClient();
        await h.Session.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.DoesNotContain(h.ServerReceived, m => m["method"]?.GetValue<string>() is "tools/call" or "notifications/cancelled");
        Assert.Contains("cancelled by the client", h.Log.ToString());
    }

    [Fact]
    public async Task ClosingTheClientClosesTheServer()
    {
        using var f = new ServiceFixture();
        await using var h = new ProxyHarness(f);
        await h.Send(new { jsonrpc = "2.0", method = "notifications/initialized" });
        await h.CloseClient();
        await h.Proxy.ClientDone.WaitAsync(TimeSpan.FromSeconds(5));
        await h.Session.WaitAsync(TimeSpan.FromSeconds(5)); // the fake server saw EOF and closed its output
        Assert.Single(h.ServerReceived);
    }

    [Fact]
    public async Task ServiceDownFailsClosedUnlessConfiguredOpen()
    {
        using var f = new ServiceFixture();
        static Task<Core.DecideResponse> Down(Core.DecideRequest r, CancellationToken ct) => throw new HttpRequestException("refused");

        await using (var closed = new ProxyHarness(f, decider: Down))
        {
            await closed.Send(ProxyHarness.ToolCall(1, "anything"));
            Assert.True((await closed.Receive())["result"]!["isError"]!.GetValue<bool>());
        }
        await using (var open = new ProxyHarness(f, failOpen: true, decider: Down))
        {
            await open.Send(ProxyHarness.ToolCall(1, "anything"));
            Assert.Equal("tools/call", (await open.Receive())["result"]!["served"]!.GetValue<string>());
        }
    }
}

public class ChildProcessTests
{
    [Fact]
    public void ResolvesCommandsLikeCmdDoes()
    {
        var dir = Path.Combine(Path.GetTempPath(), "agpath-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "npx.cmd"), "");
            File.WriteAllText(Path.Combine(dir, "uvx.exe"), "");
            Assert.Equal(Path.Combine(dir, "npx.cmd"), ChildProcess.ResolveWindows("npx", dir, ".exe;.cmd"));
            Assert.Equal(Path.Combine(dir, "uvx.exe"), ChildProcess.ResolveWindows("uvx", "/nope;" + dir, ".exe;.cmd"));
            Assert.Null(ChildProcess.ResolveWindows("missing", dir, ".exe;.cmd"));
            Assert.Equal(Path.Combine(dir, "npx.cmd"), ChildProcess.ResolveWindows(Path.Combine(dir, "npx"), "", ".exe;.cmd"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("plain", "^\"plain^\"")]
    [InlineData("a b", "^\"a b^\"")]
    [InlineData("x&calc", "^\"x^&calc^\"")]
    [InlineData("say \"hi\"", "^\"say \\^\"hi\\^\"^\"")]
    [InlineData("%PATH%", "^\"^%PATH^%^\"")]
    [InlineData("C:\\dir\\", "^\"C:\\dir\\\\^\"")]
    public void EscapesArgumentsForCmd(string input, string expected) =>
        Assert.Equal(expected, ChildProcess.EscapeForCmd(input));

    [Fact]
    public void BuildsDirectStartsOffWindows()
    {
        if (OperatingSystem.IsWindows()) return;
        var psi = ChildProcess.Build("npx", new[] { "-y", "server & more" });
        Assert.Equal("npx", psi.FileName);
        Assert.Equal(new[] { "-y", "server & more" }, psi.ArgumentList);
        Assert.True(psi.RedirectStandardInput && psi.RedirectStandardOutput && !psi.RedirectStandardError);
    }
}
