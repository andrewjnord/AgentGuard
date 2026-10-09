using System.Text;
using AgentGuard.Core;
using AgentGuard.Core.Export;
using AgentGuard.Core.Storage;
using AgentGuard.Service.Services;
using Microsoft.AspNetCore.Http.Features;

namespace AgentGuard.Service.Api;

/// <summary><c>GET /api/v1/stream</c>: Server-Sent Events for the dashboard and tray.</summary>
public static class StreamEndpoint
{
    public static readonly TimeSpan Heartbeat = TimeSpan.FromSeconds(15);

    public static async Task HandleAsync(HttpContext ctx, EventBus bus, StatusService status)
    {
        ctx.Response.Headers.ContentType = "text/event-stream";
        ctx.Response.Headers.CacheControl = "no-cache, no-store";
        ctx.Response.Headers["X-Accel-Buffering"] = "no";
        ctx.Features.Get<IHttpResponseBodyFeature>()?.DisableBuffering();

        using var sub = bus.Subscribe();
        var ct = ctx.RequestAborted;
        try
        {
            await WriteAsync(ctx, "hello", status.Status(), ct);
            Task<bool>? wait = null;
            while (!ct.IsCancellationRequested)
            {
                // Keep one outstanding wait across heartbeats: the channel has a single reader.
                wait ??= sub.Reader.WaitToReadAsync(ct).AsTask();
                var finished = await Task.WhenAny(wait, Task.Delay(Heartbeat, ct));
                if (finished != wait)
                {
                    await ctx.Response.WriteAsync(": keep-alive\n\n", ct);
                    await ctx.Response.Body.FlushAsync(ct);
                    continue;
                }
                var more = await wait;
                wait = null;
                if (!more) break;
                while (sub.Reader.TryRead(out var msg))
                {
                    var (name, data) = Map(msg, status);
                    if (name is not null) await WriteAsync(ctx, name, data, ct);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
    }

    /// <summary>Bus messages to SSE event names and payloads; internal message types are dropped.</summary>
    public static (string? Name, object? Data) Map(BusMessage msg, StatusService status) => msg.Type switch
    {
        "event" => ("event", msg.Data),
        "alert" => ("alert", msg.Data),
        "approval" => ("approval", msg.Data),
        "agentChanged" when msg.Data is string id => status.Agent(id) is { } a ? ("agent", a) : (null, null),
        "status" => ("status", status.Status()),
        _ => (null, null),
    };

    private static async Task WriteAsync(HttpContext ctx, string name, object? data, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append("event: ").Append(name).Append('\n');
        sb.Append("data: ").Append(ApiJson.Serialize(data)).Append("\n\n");
        await ctx.Response.WriteAsync(sb.ToString(), ct);
        await ctx.Response.Body.FlushAsync(ct);
    }
}

/// <summary><c>GET /api/v1/export</c>: streams events as OCSF NDJSON, AgentGuard JSON NDJSON, or CEF lines.</summary>
public static class ExportEndpoint
{
    public static async Task HandleAsync(HttpContext ctx, EventStore store, EventPipeline pipeline)
    {
        var q = ctx.Request.Query;
        var format = q["format"].ToString();
        if (format.Length == 0) format = "ocsf";
        if (format is not ("ocsf" or "cef" or "json"))
        {
            await Endpoints.Error(400, "format must be ocsf, cef or json.").ExecuteAsync(ctx);
            return;
        }
        DateTimeOffset? from = null, to = null;
        if (q["from"].ToString() is { Length: > 0 } f)
        {
            if (!DateTimeOffset.TryParse(f, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var v)) { await Endpoints.Error(400, "from must be an ISO-8601 timestamp.").ExecuteAsync(ctx); return; }
            from = v;
        }
        if (q["to"].ToString() is { Length: > 0 } t)
        {
            if (!DateTimeOffset.TryParse(t, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var v)) { await Endpoints.Error(400, "to must be an ISO-8601 timestamp.").ExecuteAsync(ctx); return; }
            to = v;
        }
        var agentId = q["agentId"].ToString() is { Length: > 0 } a ? a : null;

        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
        var (contentType, ext) = format == "cef" ? ("text/plain; charset=utf-8", "cef.log") : ("application/x-ndjson; charset=utf-8", format + ".ndjson");
        ctx.Response.ContentType = contentType;
        ctx.Response.Headers.ContentDisposition = $"attachment; filename=\"agentguard-{stamp}.{ext}\"";
        ctx.Response.Headers.CacheControl = "no-store";

        var host = Environment.MachineName;
        long cursor = 0;
        long count = 0;
        var ct = ctx.RequestAborted;
        var sb = new StringBuilder();
        while (!ct.IsCancellationRequested)
        {
            var page = store.QueryEvents(new EventFilter { From = from, To = to, AgentId = agentId, After = cursor, Ascending = true, Limit = 1000 });
            if (page.Count == 0) break;
            sb.Clear();
            foreach (var e in page)
            {
                sb.Append(format switch
                {
                    "ocsf" => OcsfMapper.Map(e, host, StatusService.Version).ToJsonString(),
                    "cef" => Cef.Format(e, host, StatusService.Version),
                    _ => ApiJson.Serialize(e),
                }).Append('\n');
            }
            await ctx.Response.WriteAsync(sb.ToString(), ct);
            count += page.Count;
            cursor = page[^1].Id;
            if (page.Count < 1000) break;
        }
        await pipeline.SystemEventAsync(Actions.System, $"Exported {count} events ({format})",
            new() { ["format"] = format, ["count"] = count, ["from"] = from?.ToString("O"), ["to"] = to?.ToString("O"), ["agentId"] = agentId });
    }
}
