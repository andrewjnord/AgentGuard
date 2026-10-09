using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using AgentGuard.Core.Integration;

namespace AgentGuard.Tray;

/// <summary>
/// The tray's link to the service: gets the admin token over the tray pipe (the service only hands it to the installed
/// tray executable), follows the live event stream, and reconnects with backoff when the service restarts.
/// </summary>
public sealed class ServiceConnection : IDisposable
{
    private const string PipeName = "AgentGuard.Tray";

    private readonly CancellationTokenSource _stop = new();
    private AgentGuardClient? _api;

    public int Port { get; } = ClientConfig.Load().Port;
    public string? Token { get; private set; }
    public bool Connected { get; private set; }

    /// <summary>Raised on the thread pool; marshal to the UI thread before touching controls.</summary>
    public event Action<TrayState>? StateChanged;
    public event Action<string>? TokenChanged;
    public event Action<JsonElement>? ApprovalChanged;
    public event Action<JsonElement>? AlertRaised;

    public void Start() => _ = Task.Run(() => RunAsync(_stop.Token));

    private async Task RunAsync(CancellationToken ct)
    {
        var delay = TimeSpan.FromSeconds(1);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var token = await ReadTokenAsync(ct);
                if (token is null)
                {
                    Publish(TrayModel.Disconnected("this copy of the tray app is not the installed one"));
                    await Task.Delay(TimeSpan.FromSeconds(30), ct);
                    continue;
                }
                if (token != Token)
                {
                    Token = token;
                    _api?.Dispose();
                    _api = new AgentGuardClient(TrayModel.DashboardOrigin(Port) + "/", token, TimeSpan.FromSeconds(30), actor: "tray");
                    TokenChanged?.Invoke(token);
                }
                await FollowStreamAsync(_api!, ct);
                delay = TimeSpan.FromSeconds(1);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) when (ex is IOException or HttpRequestException or TimeoutException or AgentGuardApiException or JsonException or UnauthorizedAccessException)
            {
                Publish(TrayModel.Disconnected(ex is TimeoutException ? "service not running" : "connection lost"));
            }
            Connected = false;
            try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { break; }
            delay = TimeSpan.FromSeconds(Math.Min(30, delay.TotalSeconds * 2));
        }
    }

    /// <summary>Returns the token, or null when the service refused this executable.</summary>
    private static async Task<string?> ReadTokenAsync(CancellationToken ct)
    {
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(2000, ct);
        using var reader = new StreamReader(pipe, Encoding.UTF8);
        var reply = (await reader.ReadToEndAsync(ct)).Trim();
        return reply.Length == 0 || reply == "DENIED" ? null : reply;
    }

    private async Task FollowStreamAsync(AgentGuardClient api, CancellationToken ct)
    {
        // Approvals created before we connected still need a prompt.
        var pending = await api.GetAsync<JsonElement>("api/v1/approvals?status=pending", ct);
        foreach (var a in pending.EnumerateArray()) ApprovalChanged?.Invoke(a);

        await using var stream = await api.OpenStreamAsync("api/v1/stream", ct);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        Connected = true;
        string? name = null;
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.StartsWith("event: ", StringComparison.Ordinal)) name = line[7..];
            else if (line.StartsWith("data: ", StringComparison.Ordinal) && name is not null)
            {
                var data = JsonDocument.Parse(line[6..]).RootElement.Clone();
                switch (name)
                {
                    case "hello":
                    case "status":
                        Publish(TrayModel.FromStatus(data));
                        break;
                    case "approval":
                        ApprovalChanged?.Invoke(data);
                        break;
                    case "alert":
                        AlertRaised?.Invoke(data);
                        break;
                }
                name = null;
            }
        }
        throw new IOException("The event stream ended.");
    }

    private void Publish(TrayState s) => StateChanged?.Invoke(s);

    private AgentGuardClient Api => _api ?? throw new InvalidOperationException("Not connected to the AgentGuard service.");

    public Task<JsonElement> SetModeAsync(string mode) => Api.SendAsync(HttpMethod.Put, "api/v1/mode", new { mode });
    public Task<JsonElement> KillSwitchAsync(string action) => Api.SendAsync(HttpMethod.Post, "api/v1/killswitch", new { action });
    public Task<JsonElement> DecideAsync(string approvalId, string decision) =>
        Api.SendAsync(HttpMethod.Post, $"api/v1/approvals/{Uri.EscapeDataString(approvalId)}", new { decision });

    public void Dispose()
    {
        _stop.Cancel();
        _api?.Dispose();
    }
}
