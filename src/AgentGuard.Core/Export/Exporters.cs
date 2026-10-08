using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace AgentGuard.Core.Export;

public interface IEventExporter
{
    string Name { get; }
    Task ExportAsync(IReadOnlyList<AgentEvent> events, CancellationToken ct);
}

/// <summary>Sends OCSF events to a Splunk HTTP Event Collector.</summary>
public sealed class SplunkHecExporter : IEventExporter, IDisposable
{
    private readonly SplunkSettings _settings;
    private readonly HttpClient _http;
    private readonly string _hostname;
    private readonly string _version;

    public string Name => "splunk";

    public SplunkHecExporter(SplunkSettings settings, string hostname, string version, HttpMessageHandler? handler = null)
    {
        _settings = settings;
        _hostname = hostname;
        _version = version;
        if (handler is null)
        {
            var h = new HttpClientHandler();
            if (!settings.VerifyTls) h.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            handler = h;
        }
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
    }

    public async Task ExportAsync(IReadOnlyList<AgentEvent> events, CancellationToken ct)
    {
        if (events.Count == 0) return;
        var body = new StringBuilder();
        foreach (var e in events)
        {
            var envelope = new JsonObject
            {
                ["time"] = e.Ts.ToUnixTimeMilliseconds() / 1000.0,
                ["host"] = _hostname,
                ["source"] = "agentguard",
                ["sourcetype"] = _settings.Sourcetype,
                ["index"] = string.IsNullOrEmpty(_settings.Index) ? null : _settings.Index,
                ["event"] = OcsfMapper.Map(e, _hostname, _version),
            };
            body.Append(envelope.ToJsonString()).Append('\n');
        }
        using var req = new HttpRequestMessage(HttpMethod.Post, _settings.Url)
        {
            Content = new StringContent(body.ToString(), Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Splunk", _settings.Token ?? "");
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var text = await resp.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException($"Splunk HEC returned {(int)resp.StatusCode}: {OcsfMapper.Truncate(text, 300)}");
        }
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>Sends CEF over syslog (RFC 5424 framing), UDP or TCP.</summary>
public sealed class SyslogExporter : IEventExporter
{
    private readonly SyslogSettings _settings;
    private readonly string _hostname;
    private readonly string _version;

    public string Name => "syslog";

    public SyslogExporter(SyslogSettings settings, string hostname, string version)
    {
        _settings = settings;
        _hostname = hostname;
        _version = version;
    }

    public async Task ExportAsync(IReadOnlyList<AgentEvent> events, CancellationToken ct)
    {
        if (events.Count == 0) return;
        var messages = events.Select(e => Encoding.UTF8.GetBytes(Frame(e))).ToList();
        if (_settings.Protocol == "tcp")
        {
            using var client = new TcpClient();
            await client.ConnectAsync(_settings.Host, _settings.Port, ct);
            await using var stream = client.GetStream();
            foreach (var m in messages)
            {
                // Octet-counting framing (RFC 6587).
                var prefix = Encoding.ASCII.GetBytes(m.Length + " ");
                await stream.WriteAsync(prefix, ct);
                await stream.WriteAsync(m, ct);
            }
        }
        else
        {
            using var udp = new UdpClient();
            foreach (var m in messages) await udp.SendAsync(m, _settings.Host, _settings.Port, ct);
        }
    }

    public string Frame(AgentEvent e)
    {
        // PRI: facility 13 (log audit) * 8 + severity.
        var sev = e.Severity switch
        {
            Severity.Critical => 2,
            Severity.High => 3,
            Severity.Medium => 4,
            Severity.Low => 5,
            _ => 6,
        };
        var pri = 13 * 8 + sev;
        return $"<{pri}>1 {e.Ts.ToUniversalTime():yyyy-MM-dd'T'HH:mm:ss.fff'Z'} {_hostname} AgentGuard - {e.Action} - {Cef.Format(e, _hostname, _version)}";
    }
}

/// <summary>Writes OCSF events as newline-delimited JSON, one file per UTC day.</summary>
public sealed class JsonFileExporter : IEventExporter
{
    private readonly string _directory;
    private readonly string _hostname;
    private readonly string _version;

    public string Name => "jsonFile";

    public JsonFileExporter(string directory, string hostname, string version)
    {
        _directory = directory;
        _hostname = hostname;
        _version = version;
    }

    public async Task ExportAsync(IReadOnlyList<AgentEvent> events, CancellationToken ct)
    {
        if (events.Count == 0) return;
        Directory.CreateDirectory(_directory);
        foreach (var group in events.GroupBy(e => e.Ts.UtcDateTime.Date))
        {
            var path = Path.Combine(_directory, $"agentguard-{group.Key:yyyy-MM-dd}.ocsf.ndjson");
            var sb = new StringBuilder();
            foreach (var e in group) sb.Append(OcsfMapper.Map(e, _hostname, _version).ToJsonString()).Append('\n');
            await File.AppendAllTextAsync(path, sb.ToString(), ct);
        }
    }
}
