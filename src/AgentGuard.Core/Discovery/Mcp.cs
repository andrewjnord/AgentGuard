using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core.Policy;

namespace AgentGuard.Core.Discovery;

/// <summary>Argument conventions for <c>agentguard-mcp-proxy --server &lt;name&gt; [--fail-open] -- &lt;command&gt; [args...]</c>.</summary>
public static class McpProxyArgs
{
    public sealed record Parsed(string Server, bool FailOpen, string Command, List<string> Args);

    public static Parsed? Parse(IReadOnlyList<string> args)
    {
        string? server = null;
        var failOpen = false;
        var i = 0;
        for (; i < args.Count; i++)
        {
            var a = args[i];
            if (a == "--") { i++; break; }
            if (a == "--server" && i + 1 < args.Count) server = args[++i];
            else if (a.StartsWith("--server=", StringComparison.Ordinal)) server = a["--server=".Length..];
            else if (a == "--fail-open") failOpen = true;
        }
        if (server is null || i >= args.Count) return null;
        return new Parsed(server, failOpen, args[i], args.Skip(i + 1).ToList());
    }

    public static List<string> Build(string server, string command, IEnumerable<string> args) =>
        new List<string> { "--server", server, "--", command }.Concat(args).ToList();

    public static string? ServerNameFromCommandLine(string commandLine)
    {
        var tokens = SplitCommandLine(commandLine);
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i] == "--") break;
            if (tokens[i] == "--server" && i + 1 < tokens.Count) return tokens[i + 1];
            if (tokens[i].StartsWith("--server=", StringComparison.Ordinal)) return tokens[i]["--server=".Length..];
        }
        return null;
    }

    /// <summary>Splits a command line using Windows quoting rules (also fine for typical POSIX command lines).</summary>
    public static List<string> SplitCommandLine(string commandLine)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;
        var hasToken = false;
        for (var i = 0; i < commandLine.Length; i++)
        {
            var c = commandLine[i];
            if (c == '\\')
            {
                var n = 0;
                while (i < commandLine.Length && commandLine[i] == '\\') { n++; i++; }
                if (i < commandLine.Length && commandLine[i] == '"')
                {
                    sb.Append('\\', n / 2);
                    if (n % 2 == 1) sb.Append('"');
                    else inQuotes = !inQuotes;
                }
                else
                {
                    sb.Append('\\', n);
                    i--;
                }
                hasToken = true;
            }
            else if (c == '"') { inQuotes = !inQuotes; hasToken = true; }
            else if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (hasToken) { result.Add(sb.ToString()); sb.Clear(); hasToken = false; }
            }
            else { sb.Append(c); hasToken = true; }
        }
        if (hasToken) result.Add(sb.ToString());
        return result;
    }
}

public static class McpConfigScanner
{
    public const string LocalForwarderPrefix = "http://127.0.0.1:47823/mcp/";

    private static readonly JsonDocumentOptions ReadOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>Finds MCP server definitions in every known client config for each user profile.</summary>
    public static List<McpServerRecord> Scan(IEnumerable<McpClientDefinition> clients, IEnumerable<string> userProfiles)
    {
        var result = new List<McpServerRecord>();
        var clientList = clients.ToList();
        foreach (var home in userProfiles.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var ctx = new PathContext(home);
            foreach (var client in clientList)
            {
                foreach (var pattern in client.Paths)
                {
                    var path = Glob.ExpandPattern(pattern, ctx);
                    if (path.Contains('%') || path.StartsWith('~')) continue; // unresolved variable
                    var native = ToNative(path);
                    if (!File.Exists(native)) continue;
                    result.AddRange(ScanFile(client, native));
                }
            }
        }
        return result.GroupBy(r => r.Id).Select(g => g.First()).ToList();
    }

    public static List<McpServerRecord> ScanFile(McpClientDefinition client, string configPath)
    {
        var result = new List<McpServerRecord>();
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(File.ReadAllText(configPath), documentOptions: ReadOptions);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            return result;
        }
        if (root is not JsonObject obj) return result;

        AddServers(result, client.Client, client.Scope, configPath, new List<string> { client.ServersKey }, obj[client.ServersKey] as JsonObject);

        if (client.ClaudeCodeProjects && obj["projects"] is JsonObject projects)
        {
            foreach (var (projectPath, projectNode) in projects)
            {
                if (projectNode is JsonObject p && p["mcpServers"] is JsonObject servers)
                    AddServers(result, client.Client, "project", configPath, new List<string> { "projects", projectPath, "mcpServers" }, servers);

                var projectFile = Path.Combine(ToNative(projectPath), ".mcp.json");
                if (File.Exists(projectFile))
                {
                    try
                    {
                        if (JsonNode.Parse(File.ReadAllText(projectFile), documentOptions: ReadOptions) is JsonObject pf && pf["mcpServers"] is JsonObject ps)
                            AddServers(result, client.Client, "project", projectFile, new List<string> { "mcpServers" }, ps);
                    }
                    catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException) { }
                }
            }
        }
        return result;
    }

    private static void AddServers(List<McpServerRecord> result, string client, string scope, string configPath, List<string> basePath, JsonObject? servers)
    {
        if (servers is null) return;
        foreach (var (name, node) in servers)
        {
            if (node is not JsonObject s) continue;
            var jsonPath = basePath.Append(name).ToList();
            var record = new McpServerRecord
            {
                Id = MakeId(client, configPath, jsonPath),
                Name = name,
                Client = client,
                ConfigPath = configPath,
                JsonPath = jsonPath,
                Scope = scope,
            };
            var url = s["url"]?.GetValue<string>() ?? s["serverUrl"]?.GetValue<string>();
            var type = s["type"]?.GetValue<string>();
            if (url is not null || type is "http" or "sse" or "streamable-http")
            {
                record.Transport = "http";
                record.Url = url;
                record.Proxied = url?.StartsWith(LocalForwarderPrefix, StringComparison.OrdinalIgnoreCase) == true;
            }
            else
            {
                record.Transport = "stdio";
                record.Command = s["command"]?.GetValue<string>();
                record.Args = (s["args"] as JsonArray)?.Select(a => a?.ToString() ?? "").ToList() ?? new List<string>();
                if (record.Command is not null && IsProxy(record.Command))
                {
                    var parsed = McpProxyArgs.Parse(record.Args);
                    if (parsed is not null)
                    {
                        record.Proxied = true;
                        record.Command = parsed.Command;
                        record.Args = parsed.Args;
                    }
                }
            }
            result.Add(record);
        }
    }

    public static bool IsProxy(string command) =>
        Path.GetFileNameWithoutExtension(command.Replace('\\', '/').Split('/').Last())
            .Equals(AgentAttributor.ProxyProcessName, StringComparison.OrdinalIgnoreCase);

    public static string MakeId(string client, string configPath, IEnumerable<string> jsonPath)
    {
        var key = client + "|" + Glob.NormalizePath(configPath).ToLowerInvariant() + "|" + string.Join("/", jsonPath);
        return Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(key)))[..16].ToLowerInvariant();
    }

    internal static string ToNative(string normalized) =>
        OperatingSystem.IsWindows() ? normalized.Replace('/', '\\') : normalized;
}

/// <summary>Rewrites MCP client configs so servers launch through the AgentGuard proxy, and back again.</summary>
public static class McpConfigRewriter
{
    private static readonly JsonDocumentOptions ReadOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static void WrapStdio(string configPath, IReadOnlyList<string> jsonPath, string proxyExePath, string serverName, bool failOpen = false)
    {
        Edit(configPath, jsonPath, server =>
        {
            var command = server["command"]?.GetValue<string>() ?? throw new InvalidOperationException("Server has no command.");
            if (McpConfigScanner.IsProxy(command)) return; // already wrapped
            var args = (server["args"] as JsonArray)?.Select(a => a?.ToString() ?? "").ToList() ?? new List<string>();
            var newArgs = new List<string> { "--server", serverName };
            if (failOpen) newArgs.Add("--fail-open");
            newArgs.Add("--");
            newArgs.Add(command);
            newArgs.AddRange(args);
            server["command"] = proxyExePath;
            server["args"] = new JsonArray(newArgs.Select(a => (JsonNode?)JsonValue.Create(a)).ToArray());
        });
    }

    public static void UnwrapStdio(string configPath, IReadOnlyList<string> jsonPath)
    {
        Edit(configPath, jsonPath, server =>
        {
            var command = server["command"]?.GetValue<string>();
            if (command is null || !McpConfigScanner.IsProxy(command)) return;
            var args = (server["args"] as JsonArray)?.Select(a => a?.ToString() ?? "").ToList() ?? new List<string>();
            var parsed = McpProxyArgs.Parse(args) ?? throw new InvalidOperationException("Proxied entry has unexpected arguments.");
            server["command"] = parsed.Command;
            server["args"] = new JsonArray(parsed.Args.Select(a => (JsonNode?)JsonValue.Create(a)).ToArray());
        });
    }

    /// <summary>Points an HTTP server at a different URL and returns the URL it had before.</summary>
    public static string? SetUrl(string configPath, IReadOnlyList<string> jsonPath, string url)
    {
        string? previous = null;
        Edit(configPath, jsonPath, server =>
        {
            var key = server.ContainsKey("serverUrl") && !server.ContainsKey("url") ? "serverUrl" : "url";
            previous = server[key]?.GetValue<string>();
            server[key] = url;
        });
        return previous;
    }

    private static void Edit(string configPath, IReadOnlyList<string> jsonPath, Action<JsonObject> mutate)
    {
        var text = File.ReadAllText(configPath);
        var root = JsonNode.Parse(text, documentOptions: ReadOptions) as JsonObject
                   ?? throw new InvalidOperationException("Config root is not a JSON object.");
        JsonObject node = root;
        foreach (var segment in jsonPath)
            node = node[segment] as JsonObject ?? throw new InvalidOperationException($"Config path '{string.Join("/", jsonPath)}' not found.");
        mutate(node);

        var backup = configPath + ".agentguard.bak";
        if (!File.Exists(backup)) File.WriteAllText(backup, text);
        var tmp = configPath + ".agentguard.tmp";
        File.WriteAllText(tmp, root.ToJsonString(WriteOptions));
        File.Move(tmp, configPath, overwrite: true);
    }
}
