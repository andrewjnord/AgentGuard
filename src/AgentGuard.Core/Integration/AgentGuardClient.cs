using System.Net.Http.Json;
using System.Text.Json;

namespace AgentGuard.Core.Integration;

/// <summary>HTTP client for the local AgentGuard service, used by the MCP proxy, hooks CLI, admin CLI and tray app.</summary>
public sealed class AgentGuardClient : IDisposable
{
    public const int DefaultPort = 47823;
    public const string TokenHeader = "X-AgentGuard-Token";

    private readonly HttpClient _http;

    public Uri BaseAddress => _http.BaseAddress!;

    public AgentGuardClient(string? baseUrl = null, string? token = null, TimeSpan? timeout = null, HttpMessageHandler? handler = null)
    {
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.BaseAddress = new Uri(baseUrl ?? DefaultBaseUrl());
        _http.Timeout = timeout ?? TimeSpan.FromSeconds(30);
        if (!string.IsNullOrEmpty(token)) _http.DefaultRequestHeaders.Add(TokenHeader, token);
    }

    public static string DefaultBaseUrl() =>
        Environment.GetEnvironmentVariable("AGENTGUARD_URL") is { Length: > 0 } url ? url.TrimEnd('/') + "/" : $"http://127.0.0.1:{DefaultPort}/";

    public async Task<DecideResponse> DecideAsync(DecideRequest request, CancellationToken ct = default)
    {
        using var resp = await _http.PostAsJsonAsync("api/v1/decide", request, Json.Options, ct);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<DecideResponse>(Json.Options, ct))!;
    }

    public async Task<T> GetAsync<T>(string path, CancellationToken ct = default)
    {
        using var resp = await _http.GetAsync(path, ct);
        await EnsureOk(resp, ct);
        return (await resp.Content.ReadFromJsonAsync<T>(Json.Options, ct))!;
    }

    public async Task<JsonElement> SendAsync(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(method, path);
        if (body is not null) req.Content = JsonContent.Create(body, options: Json.Options);
        using var resp = await _http.SendAsync(req, ct);
        await EnsureOk(resp, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        return text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone();
    }

    public async Task<Stream> OpenStreamAsync(string path, CancellationToken ct = default)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        await EnsureOk(resp, ct);
        return await resp.Content.ReadAsStreamAsync(ct);
    }

    private static async Task EnsureOk(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;
        var text = await resp.Content.ReadAsStringAsync(ct);
        throw new AgentGuardApiException((int)resp.StatusCode, text);
    }

    public void Dispose() => _http.Dispose();
}

public sealed class AgentGuardApiException : Exception
{
    public int StatusCode { get; }
    public string Body { get; }

    public AgentGuardApiException(int statusCode, string body)
        : base($"AgentGuard service returned {statusCode}: {(body.Length > 300 ? body[..300] : body)}")
    {
        StatusCode = statusCode;
        Body = body;
    }
}
