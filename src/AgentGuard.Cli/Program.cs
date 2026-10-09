namespace AgentGuard.Cli;

public static class CliProgram
{
    public static Task<int> Main(string[] args) => new AdminCli(Console.Out, Console.Error).RunAsync(args);
}
