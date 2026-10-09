using System.ComponentModel;
using System.Diagnostics;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Integration;

namespace AgentGuard.McpProxy;

/// <summary>
/// agentguard-mcp-proxy --server &lt;name&gt; [--fail-open] -- &lt;command&gt; [args...]
/// Launched by an MCP client in place of the real server (AgentGuard rewrites the client config).
/// </summary>
public static class ProxyProgram
{
    public static async Task<int> Main(string[] args)
    {
        var parsed = McpProxyArgs.Parse(args);
        if (parsed is null)
        {
            Console.Error.WriteLine("Usage: agentguard-mcp-proxy --server <name> [--fail-open] -- <command> [args...]");
            return 2;
        }

        var config = ClientConfig.Load();
        var failOpen = parsed.FailOpen || config.FailOpen;
        using var client = new AgentGuardClient(config.ResolveBaseUrl(), timeout: Timeout.InfiniteTimeSpan);
        var gate = new McpGate(parsed.Server, client.DecideAsync, failOpen)
        {
            UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Cwd = Environment.CurrentDirectory,
            Pid = Environment.ProcessId,
        };

        Process server;
        KillOnCloseJob? job = null;
        try
        {
            var psi = ChildProcess.Build(parsed.Command, parsed.Args);
            server = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null.");
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    job = new KillOnCloseJob();
                    job.Add(server);
                }
                catch (Win32Exception ex) { Console.Error.WriteLine($"[agentguard] warning: could not tie the server's lifetime to the proxy: {ex.Message}"); }
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or FileNotFoundException)
        {
            Console.Error.WriteLine($"[agentguard] could not start MCP server '{parsed.Server}' ({parsed.Command}): {ex.Message}");
            return 127;
        }

        using var stdin = Console.OpenStandardInput();
        using var stdout = Console.OpenStandardOutput();
        var session = new ProxySession(stdin, stdout, server.StandardInput.BaseStream, server.StandardOutput.BaseStream, gate, Console.Error);

        Console.CancelKeyPress += (_, e) => { e.Cancel = true; TryKill(server); };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => TryKill(server);

        var relay = session.RunAsync();
        // The server normally exits once its stdin closes; give it a few seconds, then end it.
        var gracePeriod = session.ClientDone.ContinueWith(_ => Task.Delay(TimeSpan.FromSeconds(5))).Unwrap();
        await Task.WhenAny(relay, gracePeriod);
        if (!server.HasExited) TryKill(server);
        await server.WaitForExitAsync();
        job?.Dispose();
        return server.ExitCode;
    }

    private static void TryKill(Process p)
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
    }
}
