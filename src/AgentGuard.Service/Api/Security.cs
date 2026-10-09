using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using AgentGuard.Core.Integration;

namespace AgentGuard.Service.Api;

/// <summary>The admin token for the local API. Rotates at every service start unless fixed in dev mode.</summary>
public sealed class TokenService
{
    public string Token { get; }

    public TokenService(AgentGuardOptions options, ILogger<TokenService> log)
    {
        Token = !string.IsNullOrEmpty(options.Token) && (options.DevMode || options.Demo)
            ? options.Token
            : Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (!string.IsNullOrEmpty(options.Token) && !(options.DevMode || options.Demo))
            log.LogWarning("A fixed token is only honoured in dev or demo mode; a random token was generated.");

        Directory.CreateDirectory(options.DataDir);
        if (OperatingSystem.IsWindows()) DataDirAcl.Restrict(options.DataDir);
        File.WriteAllText(options.TokenPath, Token);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(options.TokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public bool Matches(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate)) return false;
        var a = Encoding.UTF8.GetBytes(candidate);
        var b = Encoding.UTF8.GetBytes(Token);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }
}

/// <summary>Limits the data directory (database, policy, token) to SYSTEM and Administrators.</summary>
[SupportedOSPlatform("windows")]
internal static class DataDirAcl
{
    public static void Restrict(string dir)
    {
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(dir).SetAccessControl(security);
        }
        catch (Exception) { /* not elevated (dev run): leave default permissions */ }
    }
}

/// <summary>
/// Rejects cross-origin and DNS-rebinding requests and requires the admin token on management endpoints.
/// <c>/api/v1/decide</c>, <c>/api/v1/health</c> and the MCP forwarder are open to local processes: they grant no control.
/// </summary>
public sealed class LocalApiSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenService _tokens;
    private readonly HashSet<string> _allowedHosts;
    private readonly HashSet<string> _allowedOrigins;

    public LocalApiSecurityMiddleware(RequestDelegate next, TokenService tokens, AgentGuardOptions options)
    {
        _next = next;
        _tokens = tokens;
        _allowedHosts = new(StringComparer.OrdinalIgnoreCase) { $"127.0.0.1:{options.Port}", $"localhost:{options.Port}", "localhost" };
        _allowedOrigins = new(StringComparer.OrdinalIgnoreCase) { $"http://127.0.0.1:{options.Port}", $"http://localhost:{options.Port}" };
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var host = ctx.Request.Host.Value ?? "";
        if (!_allowedHosts.Contains(host))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { error = "Host not allowed." });
            return;
        }
        var origin = ctx.Request.Headers.Origin.ToString();
        if (origin.Length > 0 && !_allowedOrigins.Contains(origin))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new { error = "Cross-origin requests are not allowed." });
            return;
        }

        var path = ctx.Request.Path.Value ?? "";
        var open = path is "/api/v1/health" or "/api/v1/decide" || path.StartsWith("/mcp/", StringComparison.Ordinal);
        if (path.StartsWith("/api/", StringComparison.Ordinal) && !open)
        {
            var token = ctx.Request.Headers[AgentGuardClient.TokenHeader].ToString();
            if (token.Length == 0) token = ctx.Request.Query["token"].ToString();
            if (!_tokens.Matches(token))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsJsonAsync(new { error = "Missing or invalid AgentGuard token." });
                return;
            }
        }
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        await _next(ctx);
    }
}

/// <summary>
/// Hands the admin token to the AgentGuard tray app over a named pipe. On Windows the pipe checks that the
/// connecting process is the installed tray executable before answering.
/// </summary>
public sealed class TrayPipeServer : BackgroundService
{
    public const string PipeName = "AgentGuard.Tray";

    private readonly TokenService _tokens;
    private readonly AgentGuardOptions _options;
    private readonly ILogger<TrayPipeServer> _log;

    public TrayPipeServer(TokenService tokens, AgentGuardOptions options, ILogger<TrayPipeServer> log)
    {
        _tokens = tokens;
        _options = options;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(ct);
                var allowed = _options.DevMode || ClientIsTray(pipe);
                var reply = Encoding.UTF8.GetBytes(allowed ? _tokens.Token : "DENIED");
                await pipe.WriteAsync(reply, ct);
                await pipe.FlushAsync(ct);
                pipe.WaitForPipeDrain();
                if (!allowed) _log.LogWarning("Rejected a token request from a process that is not the AgentGuard tray app.");
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Tray pipe error.");
                await Task.Delay(1000, ct);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, 4, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint processId);

    [SupportedOSPlatform("windows")]
    private bool ClientIsTray(NamedPipeServerStream pipe)
    {
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid)) return false;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById((int)pid);
            var path = p.MainModule?.FileName;
            return path is not null && string.Equals(Path.GetFullPath(path), Path.GetFullPath(_options.TrayPath), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
