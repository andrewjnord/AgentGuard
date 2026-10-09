using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core.Integration;

namespace AgentGuard.McpProxy;

/// <summary>
/// Relays newline-delimited JSON-RPC between an MCP client (our stdin/stdout) and a tool server (its stdin/stdout),
/// checking each <c>tools/call</c> with AgentGuard first. Tool calls are checked concurrently, so one call waiting
/// for a person's approval never holds up pings, other calls or the server's replies; a client cancellation of a
/// call that is still being checked drops it.
/// </summary>
public sealed class ProxySession
{
    private readonly Stream _clientIn;
    private readonly Stream _clientOut;
    private readonly Stream _serverIn;
    private readonly Stream _serverOut;
    private readonly McpGate _gate;
    private readonly TextWriter _log;
    private readonly SemaphoreSlim _clientWrite = new(1, 1);
    private readonly SemaphoreSlim _serverWrite = new(1, 1);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _checking = new();
    private readonly List<Task> _inFlight = new();

    private int _blocked;
    private int _forwarded;
    public int Blocked => _blocked;
    public int Forwarded => _forwarded;

    public ProxySession(Stream clientIn, Stream clientOut, Stream serverIn, Stream serverOut, McpGate gate, TextWriter? log = null)
    {
        _clientIn = clientIn;
        _clientOut = clientOut;
        _serverIn = serverIn;
        _serverOut = serverOut;
        _gate = gate;
        _log = log ?? TextWriter.Null;
    }

    private readonly TaskCompletionSource _clientDone = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes when the client has closed its side and every pending check has finished (the server's stdin is then closed).</summary>
    public Task ClientDone => _clientDone.Task;

    /// <summary>Runs until the server closes its output: because it exited, or because the client closed and the server then finished.</summary>
    public async Task RunAsync(CancellationToken ct = default)
    {
        _ = Task.Run(async () =>
        {
            try { await ClientToServerAsync(ct); }
            catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
            Task[] pending;
            lock (_inFlight) pending = _inFlight.ToArray();
            try { await Task.WhenAll(pending); } catch { }
            try { _serverIn.Close(); } catch (IOException) { }
            _clientDone.TrySetResult();
        }, CancellationToken.None);
        try { await ServerToClientAsync(ct); }
        catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
    }

    private async Task ClientToServerAsync(CancellationToken ct)
    {
        using var reader = new StreamReader(_clientIn, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, bufferSize: 64 * 1024, leaveOpen: true);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.Length == 0) continue;
            var (kind, id, cancelledId) = Classify(line);
            switch (kind)
            {
                case Kind.ToolCall:
                    StartCheck(line, id!);
                    break;
                case Kind.Batch:
                    await HandleCheckedAsync(line, ct);
                    break;
                default:
                    if (cancelledId is not null && _checking.TryRemove(cancelledId, out var cts))
                    {
                        cts.Cancel(); // the call never reached the server, so the cancellation need not either
                        break;
                    }
                    await WriteServerAsync(line, ct);
                    break;
            }
        }
    }

    private void StartCheck(string line, string id)
    {
        var cts = new CancellationTokenSource();
        _checking[id] = cts;
        var task = Task.Run(async () =>
        {
            try { await HandleCheckedAsync(line, cts.Token); }
            catch (OperationCanceledException) when (cts.IsCancellationRequested) { await _log.WriteLineAsync($"[agentguard] tool call {id} cancelled by the client while it was being checked."); }
            finally
            {
                _checking.TryRemove(new KeyValuePair<string, CancellationTokenSource>(id, cts));
                cts.Dispose();
            }
        });
        lock (_inFlight)
        {
            _inFlight.RemoveAll(t => t.IsCompleted);
            _inFlight.Add(task);
        }
    }

    private async Task HandleCheckedAsync(string line, CancellationToken ct)
    {
        var result = await _gate.CheckAsync(line, ct);
        foreach (var call in result.Calls.Where(c => !c.Allowed))
        {
            Interlocked.Increment(ref _blocked);
            await _log.WriteLineAsync($"[agentguard] blocked {call.Tool}: {call.Reason}");
        }
        if (result.Reply is not null) await WriteClientAsync(result.Reply, CancellationToken.None);
        if (result.Forward is not null)
        {
            Interlocked.Increment(ref _forwarded);
            await WriteServerAsync(result.Forward, ct);
        }
    }

    private async Task ServerToClientAsync(CancellationToken ct)
    {
        using var reader = new StreamReader(_serverOut, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, bufferSize: 64 * 1024, leaveOpen: true);
        while (await reader.ReadLineAsync(ct) is { } line)
            await WriteClientAsync(line, ct);
    }

    private async Task WriteServerAsync(string line, CancellationToken ct)
    {
        await _serverWrite.WaitAsync(ct);
        try
        {
            var bytes = Encoding.UTF8.GetBytes(line + "\n");
            await _serverIn.WriteAsync(bytes, ct);
            await _serverIn.FlushAsync(ct);
        }
        catch (IOException) { /* server exited; its exit ends the session */ }
        finally { _serverWrite.Release(); }
    }

    private async Task WriteClientAsync(string line, CancellationToken ct)
    {
        await _clientWrite.WaitAsync(ct);
        try
        {
            var bytes = Encoding.UTF8.GetBytes(line + "\n");
            await _clientOut.WriteAsync(bytes, ct);
            await _clientOut.FlushAsync(ct);
        }
        catch (IOException) { }
        finally { _clientWrite.Release(); }
    }

    private enum Kind { Other, ToolCall, Batch }

    private static (Kind Kind, string? Id, string? CancelledId) Classify(string line)
    {
        try
        {
            var node = JsonNode.Parse(line);
            if (node is JsonArray) return (Kind.Batch, null, null);
            if (node is not JsonObject o || o["method"] is not JsonValue m || m.GetValueKind() != JsonValueKind.String) return (Kind.Other, null, null);
            var method = m.GetValue<string>();
            if (method == "tools/call") return (Kind.ToolCall, o["id"]?.ToJsonString() ?? "null", null);
            if (method == "notifications/cancelled" && o["params"]?["requestId"] is { } rid) return (Kind.Other, null, rid.ToJsonString());
        }
        catch (JsonException) { }
        return (Kind.Other, null, null);
    }
}
