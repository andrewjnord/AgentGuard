using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Integration;
using Xunit;

namespace AgentGuard.Core.Tests;

public class AttributionTests
{
    private static SignatureFile Sigs => SignatureFile.Load(Path.Combine(Repo.Root, "signatures", "agents.yaml"));
    private static readonly DateTimeOffset T0 = DateTimeOffset.UtcNow.AddMinutes(-10);

    private static ProcessInfo P(int pid, int? ppid, string name, string? exe = null, string? cmd = null, int minutes = 0) =>
        new(pid, ppid, name, exe, cmd ?? name, T0.AddMinutes(minutes));

    [Fact]
    public void SignaturesLoad()
    {
        var s = Sigs;
        Assert.Contains(s.Agents, a => a.Id == "claude-code");
        Assert.Contains(s.McpClients, c => c.Client == "Claude Code" && c.ClaudeCodeProjects);
        Assert.Contains("cmd.exe", s.Shells);
    }

    [Fact]
    public void AttributesAgentsAndChildren()
    {
        var a = new AgentAttributor(Sigs);
        var diff = a.Update(new[]
        {
            P(1, null, "explorer.exe"),
            P(10, 1, "claude.exe", @"C:\Users\ana\AppData\Local\AnthropicClaude\app-1.0\claude.exe", minutes: 1),
            P(11, 10, "claude.exe", @"C:\Users\ana\AppData\Local\AnthropicClaude\app-1.0\claude.exe", minutes: 1),
            P(20, 1, "claude.exe", @"C:\Users\ana\.local\bin\claude.exe", minutes: 2),
            P(21, 20, "pwsh.exe", minutes: 3),
            P(22, 21, "git.exe", cmd: "git status", minutes: 4),
            P(30, 1, "node.exe", cmd: @"node C:\npm\node_modules\@anthropic-ai\claude-code\cli.js", minutes: 2),
            P(40, 1, "notepad.exe"),
            P(50, 10, "agentguard-mcp-proxy.exe", cmd: "agentguard-mcp-proxy.exe --server github -- npx -y @modelcontextprotocol/server-github", minutes: 2),
            P(51, 50, "node.exe", cmd: "node server-github", minutes: 2),
            P(60, 1, "AgentGuard.Service.exe"),
        });

        Assert.Equal("claude-desktop", a.Get(10)!.AgentId);
        Assert.Equal("claude-desktop", a.Get(11)!.AgentId);
        Assert.True(a.Get(10)!.IsRoot);
        Assert.Equal("claude-code", a.Get(20)!.AgentId);
        Assert.Equal("claude-code", a.Get(22)!.AgentId);
        Assert.False(a.Get(22)!.IsRoot);
        Assert.True(a.Get(21)!.IsShell);
        Assert.Equal("claude-code", a.Get(30)!.AgentId);
        Assert.Null(a.Get(40));
        Assert.Equal("mcp:github", a.Get(50)!.AgentId);
        Assert.Equal("mcp:github", a.Get(51)!.AgentId);
        Assert.Null(a.Get(60));
        Assert.Equal(8, diff.Started.Count);
        Assert.Empty(diff.Exited);

        var diff2 = a.Update(new[] { P(1, null, "explorer.exe"), P(20, 1, "claude.exe", @"C:\Users\ana\.local\bin\claude.exe", minutes: 2) });
        Assert.Empty(diff2.Started);
        Assert.Equal(7, diff2.Exited.Count);
        Assert.Equal(new[] { 20 }, a.PidsFor("claude-code"));
    }

    [Fact]
    public void PidReuseDoesNotInherit()
    {
        var a = new AgentAttributor(Sigs);
        // Parent pid 5 started after the child: the real parent died and the pid was reused.
        a.Update(new[] { P(5, null, "Cursor.exe", minutes: 5), P(6, 5, "python.exe", minutes: 1) });
        Assert.Equal("cursor", a.Get(5)!.AgentId);
        Assert.Null(a.Get(6));
    }

    [Fact]
    public void AddAttributesRealTimeChild()
    {
        var a = new AgentAttributor(Sigs);
        a.Update(new[] { P(20, 1, "Cursor.exe") });
        var child = a.Add(P(99, 20, "cmd.exe", cmd: "cmd /c dir", minutes: 1));
        Assert.Equal("cursor", child!.AgentId);
        Assert.True(child.IsShell);
        Assert.NotNull(a.Remove(99));
    }

    [Theory]
    [InlineData("agentguard-mcp-proxy.exe --server github -- npx x", "github")]
    [InlineData("\"C:\\Program Files\\AgentGuard\\agentguard-mcp-proxy.exe\" --server \"my server\" -- node s.js", "my server")]
    [InlineData("agentguard-mcp-proxy --server=fs -- node s.js", "fs")]
    [InlineData("agentguard-mcp-proxy -- node --server x", null)]
    public void ProxyServerName(string cmd, string? expected) => Assert.Equal(expected, McpProxyArgs.ServerNameFromCommandLine(cmd));

    [Fact]
    public void SplitsWindowsCommandLines()
    {
        Assert.Equal(new[] { "a b", "c\"d", "e\\f" }, McpProxyArgs.SplitCommandLine("\"a b\" c\\\"d e\\f"));
    }
}

public class McpConfigTests
{
    [Fact]
    public void ScansWrapsAndUnwrapsClaudeDesktopConfig()
    {
        using var dir = new TempDir();
        var home = dir.Path;
        var cfgDir = Path.Combine(home, "AppData", "Roaming", "Claude");
        Directory.CreateDirectory(cfgDir);
        var cfg = Path.Combine(cfgDir, "claude_desktop_config.json");
        File.WriteAllText(cfg, """
            {
              // comments are allowed
              "mcpServers": {
                "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\ana\\Desktop"], "env": { "A": "1" } },
                "remote": { "type": "http", "url": "https://mcp.example.com/mcp" }
              },
              "globalShortcut": "Ctrl+Space",
            }
            """);
        var client = new McpClientDefinition { Client = "Claude Desktop", Paths = { "%APPDATA%/Claude/claude_desktop_config.json" } };

        var servers = McpConfigScanner.Scan(new[] { client }, new[] { home });
        Assert.Equal(2, servers.Count);
        var fs = servers.Single(s => s.Name == "filesystem");
        Assert.Equal("stdio", fs.Transport);
        Assert.False(fs.Proxied);
        Assert.Equal("npx", fs.Command);
        Assert.Equal("mcp:filesystem", fs.AgentId);
        var remote = servers.Single(s => s.Name == "remote");
        Assert.Equal("http", remote.Transport);

        McpConfigRewriter.WrapStdio(fs.ConfigPath, fs.JsonPath, @"C:\Program Files\AgentGuard\agentguard-mcp-proxy.exe", "filesystem");
        Assert.True(File.Exists(cfg + ".agentguard.bak"));
        var wrapped = McpConfigScanner.Scan(new[] { client }, new[] { home }).Single(s => s.Name == "filesystem");
        Assert.True(wrapped.Proxied);
        Assert.Equal("npx", wrapped.Command);
        Assert.Equal(3, wrapped.Args.Count);
        Assert.Equal(fs.Id, wrapped.Id);
        var json = JsonNode.Parse(File.ReadAllText(cfg))!;
        Assert.Equal("1", (string)json["mcpServers"]!["filesystem"]!["env"]!["A"]!);
        Assert.Equal("Ctrl+Space", (string)json["globalShortcut"]!);
        Assert.Equal("--server", (string)json["mcpServers"]!["filesystem"]!["args"]![0]!);

        // Wrapping twice is a no-op.
        McpConfigRewriter.WrapStdio(fs.ConfigPath, fs.JsonPath, @"C:\Program Files\AgentGuard\agentguard-mcp-proxy.exe", "filesystem");
        Assert.Equal(7, JsonNode.Parse(File.ReadAllText(cfg))!["mcpServers"]!["filesystem"]!["args"]!.AsArray().Count);

        McpConfigRewriter.UnwrapStdio(fs.ConfigPath, fs.JsonPath);
        var restored = JsonNode.Parse(File.ReadAllText(cfg))!["mcpServers"]!["filesystem"]!;
        Assert.Equal("npx", (string)restored["command"]!);
        Assert.Equal(3, restored["args"]!.AsArray().Count);

        var previous = McpConfigRewriter.SetUrl(remote.ConfigPath, remote.JsonPath, McpConfigScanner.LocalForwarderPrefix + remote.Id);
        Assert.Equal("https://mcp.example.com/mcp", previous);
        Assert.True(McpConfigScanner.Scan(new[] { client }, new[] { home }).Single(s => s.Name == "remote").Proxied);
    }

    [Fact]
    public void ScansClaudeCodeUserProjectAndDotMcpJson()
    {
        using var dir = new TempDir();
        var project = Path.Combine(dir.Path, "proj");
        Directory.CreateDirectory(project);
        File.WriteAllText(Path.Combine(project, ".mcp.json"), """{ "mcpServers": { "pg": { "command": "uvx", "args": ["mcp-server-postgres"] } } }""");
        var claudeJson = Path.Combine(dir.Path, ".claude.json");
        File.WriteAllText(claudeJson, JsonSerializer.Serialize(new
        {
            mcpServers = new { github = new { command = "npx", args = new[] { "-y", "gh" } } },
            projects = new Dictionary<string, object> { [project] = new { mcpServers = new { local1 = new { command = "python", args = new[] { "s.py" } } } } },
        }));
        var client = new McpClientDefinition { Client = "Claude Code", Paths = { "~/.claude.json" }, ClaudeCodeProjects = true };
        var servers = McpConfigScanner.Scan(new[] { client }, new[] { dir.Path });
        Assert.Equal(new[] { "github", "local1", "pg" }, servers.Select(s => s.Name).OrderBy(n => n));
        Assert.Equal("project", servers.Single(s => s.Name == "pg").Scope);
        var local = servers.Single(s => s.Name == "local1");
        Assert.Equal(new[] { "projects", project, "mcpServers", "local1" }, local.JsonPath);

        McpConfigRewriter.WrapStdio(local.ConfigPath, local.JsonPath, "agentguard-mcp-proxy", "local1");
        Assert.True(McpConfigScanner.Scan(new[] { client }, new[] { dir.Path }).Single(s => s.Name == "local1").Proxied);
    }

    [Fact]
    public void ProxyArgsRoundTrip()
    {
        var args = McpProxyArgs.Build("github", "npx", new[] { "-y", "--server", "x" });
        var parsed = McpProxyArgs.Parse(args)!;
        Assert.Equal("github", parsed.Server);
        Assert.Equal("npx", parsed.Command);
        Assert.Equal(new[] { "-y", "--server", "x" }, parsed.Args);
        Assert.Null(McpProxyArgs.Parse(new[] { "--server", "x" }));
        Assert.True(McpProxyArgs.Parse(new[] { "--server", "x", "--fail-open", "--", "node" })!.FailOpen);
    }
}

public class HookMapperTests
{
    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void MapsBash()
    {
        var r = Assert.Single(ClaudeHookMapper.Map(J("""
            { "session_id": "s1", "cwd": "C:\\src\\app", "hook_event_name": "PreToolUse", "tool_name": "Bash",
              "tool_input": { "command": "rm -rf build", "description": "clean" }, "tool_use_id": "toolu_1" }
            """), @"C:\Users\ana"));
        Assert.Equal(Actions.ShellExec, r.Action);
        Assert.Equal("rm -rf build", r.Target);
        Assert.Equal("claude-code", r.AgentId);
        Assert.Equal(@"C:\src\app", r.Cwd);
        Assert.Equal("Bash", r.Details!["tool"]);
        Assert.Equal(EventSources.Hook, r.Source);
    }

    [Fact]
    public void MapsFileToolsResolvingRelativePaths()
    {
        var cwd = Path.Combine(Path.GetTempPath(), "proj");
        var read = Assert.Single(ClaudeHookMapper.Map(J($$"""{ "cwd": {{JsonSerializer.Serialize(cwd)}}, "tool_name": "Read", "tool_input": { "file_path": "src/a.cs" } }"""), "/home/ana"));
        Assert.Equal(Actions.FileRead, read.Action);
        Assert.Equal(Path.Combine(cwd, "src", "a.cs"), read.Target);
        var home = Assert.Single(ClaudeHookMapper.Map(J("""{ "tool_name": "Read", "tool_input": { "file_path": "~/.ssh/id_rsa" } }"""), "/home/ana"));
        Assert.Equal(Path.Combine("/home/ana", ".ssh/id_rsa"), home.Target);
        Assert.Equal(Actions.FileWrite, ClaudeHookMapper.Map(J("""{ "tool_name": "Edit", "tool_input": { "file_path": "/x/y" } }"""), null)[0].Action);
        Assert.Equal(Actions.NetConnect, ClaudeHookMapper.Map(J("""{ "tool_name": "WebFetch", "tool_input": { "url": "https://x.dev/a" } }"""), null)[0].Action);
        Assert.Equal("agent.tool", ClaudeHookMapper.Map(J("""{ "tool_name": "TodoWrite", "tool_input": {} }"""), null)[0].Action);
    }

    [Fact]
    public void MapsMcpToolsWithDerivedChecks()
    {
        var list = ClaudeHookMapper.Map(J("""
            { "cwd": "/w", "tool_name": "mcp__filesystem__read_file", "tool_input": { "path": "/home/ana/.ssh/id_rsa" } }
            """), "/home/ana");
        Assert.Equal(2, list.Count);
        Assert.Equal(Actions.McpCall, list[0].Action);
        Assert.Equal("filesystem/read_file", list[0].Target);
        Assert.Equal(Actions.FileRead, list[1].Action);
        Assert.Equal("/home/ana/.ssh/id_rsa", list[1].Target);
    }

    [Fact]
    public void OutputMatchesClaudeCodeSchema()
    {
        var o = J(ClaudeHookMapper.Output(false, "Blocked by AgentGuard"));
        var h = o.GetProperty("hookSpecificOutput");
        Assert.Equal("PreToolUse", h.GetProperty("hookEventName").GetString());
        Assert.Equal("deny", h.GetProperty("permissionDecision").GetString());
        Assert.Equal("Blocked by AgentGuard", h.GetProperty("permissionDecisionReason").GetString());
    }

    [Fact]
    public void ArgumentInspectorClassifiesByToolName()
    {
        var args = J("""{ "path": "/a", "paths": ["/b", "/c"], "url": "https://x.io", "command": "ls", "other": 3 }""");
        var read = McpArgumentInspector.Derive("read_multiple_files", args);
        Assert.Equal(3, read.Count(d => d.Action == Actions.FileRead));
        Assert.Single(read, d => d.Action == Actions.NetConnect);
        Assert.Single(read, d => d.Action == Actions.ShellExec);
        Assert.All(McpArgumentInspector.Derive("write_file", J("""{ "path": "/a" }""")), d => Assert.Equal(Actions.FileWrite, d.Action));
        Assert.All(McpArgumentInspector.Derive("delete_file", J("""{ "path": "/a" }""")), d => Assert.Equal(Actions.FileDelete, d.Action));
    }
}
