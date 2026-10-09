using System.Text;
using System.Text.Json.Nodes;
using AgentGuard.Core;
using AgentGuard.Core.Integration;
using AgentGuard.Service.Services;

namespace AgentGuard.Service.Api;

/// <summary>
/// <c>/mcp/{serverId}</c>: forwards a proxied HTTP (Streamable HTTP) MCP server, checking each <c>tools/call</c> with the
/// policy first. The upstream URL always comes from AgentGuard's own record of the server, never from the request.
/// </summary>
public static class McpForwarder
{
    public const string HttpClientName = "mcp-upstream";
    private const int MaxBody = 4 * 1024 * 1024;

    private static readonly HashSet<string> SkipRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Content-Length", "Content-Type", "Connection", "Transfer-Encoding", "Origin", "Referer", "Cookie", "Keep-Alive", "Upgrade",
        "Proxy-Connection", "Proxy-Authorization", Endpoints.ActorHeader, AgentGuardClient.TokenHeader,
    };

    private static readonly HashSet<string> SkipResponseHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Transfer-Encoding", "Connection", "Keep-Alive", "Set-Cookie", "Content-Length",
    };

    public static void MapMcpForwarder(this WebApplication app)
    {
        app.Map("/mcp/{id}", (HttpContext ctx, string id, McpManager mcp, DecisionService d, IHttpClientFactory f) => HandleAsync(ctx, id, null, mcp, d, f));
        app.Map("/mcp/{id}/{**rest}", (HttpContext ctx, string id, string? rest, McpManager mcp, DecisionService d, IHttpClientFactory f) => HandleAsync(ctx, id, rest, mcp, d, f));
    }

    public static async Task HandleAsync(HttpContext ctx, string id, string? rest, McpManager mcp, DecisionService decisions, IHttpClientFactory factory)
    {
        var server = mcp.Get(id);
        if (server is null || !server.Proxied || string.IsNullOrEmpty(server.UpstreamUrl))
        {
            ctx.Response.StatusCode = 404;
            await ctx.Response.WriteAsJsonAsync(new { error = "No proxied MCP server with this id." });
            return;
        }

        var upstream = server.UpstreamUrl.TrimEnd('/') + (string.IsNullOrEmpty(rest) ? "" : "/" + rest) + ctx.Request.QueryString.Value;
        if (string.IsNullOrEmpty(rest) && server.UpstreamUrl.EndsWith('/')) upstream = server.UpstreamUrl + ctx.Request.QueryString.Value;

        string? body = null;
        if (HttpMethods.IsPost(ctx.Request.Method))
        {
            body = await ReadBodyAsync(ctx.Request);
            if (body is null)
            {
                ctx.Response.StatusCode = 413;
                return;
            }
            var gate = new McpGate(server.Name, (r, ct) => decisions.DecideAsync(r, ct)) { Source = EventSources.McpProxy, ClientName = server.Client };
            var result = await gate.CheckAsync(body, ctx.RequestAborted);
            if (result.Reply is not null)
            {
                // Block the whole message if any call in it is blocked: partial batches would leave the client waiting.
                var reply = result.Forward is null ? result.Reply : WholeBatchBlocked(body, result);
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(reply, ctx.RequestAborted);
                return;
            }
        }

        using var req = new HttpRequestMessage(new HttpMethod(ctx.Request.Method), upstream);
        if (body is not null)
            req.Content = new StringContent(body, Encoding.UTF8, ctx.Request.ContentType?.Split(';')[0].Trim() is { Length: > 0 } ctype ? ctype : "application/json");
        foreach (var h in ctx.Request.Headers)
        {
            if (SkipRequestHeaders.Contains(h.Key)) continue;
            req.Headers.TryAddWithoutValidation(h.Key, h.Value.ToArray());
        }

        var http = factory.CreateClient(HttpClientName);
        HttpResponseMessage resp;
        try { resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ctx.RequestAborted); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ctx.RequestAborted.IsCancellationRequested)
        {
            ctx.Response.StatusCode = 502;
            await ctx.Response.WriteAsJsonAsync(new { error = "The MCP server could not be reached: " + ex.Message });
            return;
        }
        using (resp)
        {
            ctx.Response.StatusCode = (int)resp.StatusCode;
            foreach (var h in resp.Headers.Concat(resp.Content.Headers))
            {
                if (SkipResponseHeaders.Contains(h.Key)) continue;
                ctx.Response.Headers[h.Key] = h.Value.ToArray();
            }
            await using var stream = await resp.Content.ReadAsStreamAsync(ctx.RequestAborted);
            var buffer = new byte[16 * 1024];
            int n;
            try
            {
                while ((n = await stream.ReadAsync(buffer, ctx.RequestAborted)) > 0)
                {
                    await ctx.Response.Body.WriteAsync(buffer.AsMemory(0, n), ctx.RequestAborted);
                    await ctx.Response.Body.FlushAsync(ctx.RequestAborted); // streamed (SSE) responses must not be held back
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
        }
    }

    private static async Task<string?> ReadBodyAsync(HttpRequest request)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[16 * 1024];
        int n;
        while ((n = await request.Body.ReadAsync(buffer)) > 0)
        {
            ms.Write(buffer, 0, n);
            if (ms.Length > MaxBody) return null;
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static string WholeBatchBlocked(string body, McpGate.Result result)
    {
        var replies = new JsonArray();
        var blocked = result.Calls.Where(c => !c.Allowed).ToList();
        foreach (var c in blocked) replies.Add(McpGate.BlockedReply(c.Id, c.Reason));
        if (JsonNode.Parse(body) is JsonArray batch)
        {
            foreach (var item in batch.OfType<JsonObject>())
            {
                if (item["id"] is not { } itemId) continue; // notifications get no reply
                if (blocked.Any(b => JsonNode.DeepEquals(b.Id, itemId))) continue;
                replies.Add(new JsonObject
                {
                    ["jsonrpc"] = "2.0",
                    ["id"] = itemId.DeepClone(),
                    ["error"] = new JsonObject { ["code"] = -32001, ["message"] = "Not sent: this batch contained a call blocked by AgentGuard." },
                });
            }
        }
        return replies.ToJsonString();
    }
}
