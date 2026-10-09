using System.Text.Json;
using AgentGuard.Core;
using AgentGuard.Core.Integration;

namespace AgentGuard.Hook;

/// <summary>
/// One Claude Code PreToolUse call: read the payload, ask AgentGuard about every action it implies, and answer.
/// AgentGuard only ever denies. When it allows, the hook prints nothing so Claude Code's own permission rules and
/// prompts still apply (a hook "allow" would skip them).
/// </summary>
public sealed class HookRunner
{
    public const int MaxInputBytes = 4 * 1024 * 1024;

    private readonly McpGate.Decider _decide;
    private readonly bool _failOpen;

    public string? UserProfile { get; init; }
    public int? Pid { get; init; }

    public HookRunner(McpGate.Decider decide, bool failOpen)
    {
        _decide = decide;
        _failOpen = failOpen;
    }

    /// <returns>The process exit code: 0 normally (a denial is in the JSON on stdout), 2 when blocking without valid input.</returns>
    public async Task<int> RunAsync(string input, TextWriter stdout, TextWriter stderr, CancellationToken ct = default)
    {
        JsonElement payload;
        try { payload = JsonDocument.Parse(input).RootElement.Clone(); }
        catch (JsonException ex)
        {
            if (_failOpen)
            {
                await stderr.WriteLineAsync($"AgentGuard: could not read the hook input ({ex.Message}); allowed (fail-open).");
                return 0;
            }
            // Exit code 2 blocks regardless of stdout.
            await stderr.WriteLineAsync($"Blocked by AgentGuard: the hook input could not be read ({ex.Message}).");
            return 2;
        }

        var requests = ClaudeHookMapper.Map(payload, UserProfile, Pid);
        foreach (var req in requests)
        {
            DecideResponse verdict;
            try { verdict = await _decide(req, ct); }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or AgentGuardApiException or IOException)
            {
                if (_failOpen)
                {
                    await stderr.WriteLineAsync("AgentGuard is not reachable; allowed (fail-open).");
                    return 0;
                }
                await stdout.WriteLineAsync(ClaudeHookMapper.Output(false,
                    "Blocked by AgentGuard: the AgentGuard service is not reachable, so tool use is blocked (fail-closed). Ask your administrator to check the AgentGuard service."));
                return 0;
            }
            if (!verdict.Allowed)
            {
                await stdout.WriteLineAsync(ClaudeHookMapper.Output(false, verdict.Reason));
                return 0;
            }
        }
        return 0; // no output: defer to Claude Code's normal permission flow
    }
}
