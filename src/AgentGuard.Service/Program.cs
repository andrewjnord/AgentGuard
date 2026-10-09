using System.Net;
using AgentGuard.Core.Discovery;
using AgentGuard.Core.Storage;
using AgentGuard.Service;
using AgentGuard.Service.Api;
using AgentGuard.Service.Platform;
using AgentGuard.Service.Services;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = ServiceArgs.Normalize(args),
    // A Windows service starts in System32; the dashboard and defaults live next to the executable.
    ContentRootPath = AppContext.BaseDirectory,
});

builder.Host.UseWindowsService(o => o.ServiceName = "AgentGuard");
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

// Everything that depends on configuration is resolved lazily, so tests (and the installer) can override it.
builder.Services.AddSingleton(sp =>
{
    var o = new AgentGuardOptions();
    sp.GetRequiredService<IConfiguration>().GetSection(AgentGuardOptions.Section).Bind(o);
    o.ApplyDefaults();
    return o;
});

builder.WebHost.ConfigureKestrel((ctx, k) =>
{
    var port = ctx.Configuration.GetValue($"{AgentGuardOptions.Section}:Port", 47823);
    k.AddServerHeader = false;
    k.Limits.MaxRequestBodySize = 8 * 1024 * 1024;
    k.Listen(IPAddress.Loopback, port); // never reachable from the network
});

builder.Services.ConfigureHttpJsonOptions(o => ApiJson.Apply(o.SerializerOptions));

builder.Services.AddSingleton(sp => new EventStore(sp.GetRequiredService<AgentGuardOptions>().DatabasePath));
builder.Services.AddSingleton(sp => SignatureFile.Load(sp.GetRequiredService<AgentGuardOptions>().SignaturesPath));
builder.Services.AddSingleton<AgentAttributor>();
builder.Services.AddSingleton<AgentRegistry>();
builder.Services.AddSingleton<PolicyManager>();
builder.Services.AddSingleton<SettingsManager>();
builder.Services.AddSingleton<KillSwitch>();
builder.Services.AddSingleton<EventBus>();
builder.Services.AddSingleton<EventPipeline>();
builder.Services.AddSingleton<ApprovalBroker>();
builder.Services.AddSingleton<McpManager>();
builder.Services.AddSingleton<DecisionService>();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton(_ => PlatformFactory.ProcessSource());
builder.Services.AddSingleton(sp => PlatformFactory.Adapters(sp.GetRequiredService<AgentGuardOptions>()));
builder.Services.AddSingleton<EnforcementService>();
builder.Services.AddSingleton<ObservationService>();
builder.Services.AddSingleton<AgentLifecycle>();
builder.Services.AddSingleton<StatusService>();
builder.Services.AddSingleton<Ops>();

builder.Services.AddHttpClient(McpForwarder.HttpClientName, c => c.Timeout = Timeout.InfiniteTimeSpan)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });

builder.Services.AddHostedService<StartupTasks>();
builder.Services.AddHostedService<TrayPipeServer>();
// Registered as IHostedService directly: AddHostedService would de-duplicate the two ConditionalWorker registrations.
builder.Services.AddSingleton<IHostedService>(sp => new ConditionalWorker(sp, o => !o.DisableWorkers, typeof(DiscoveryWorker), typeof(TelemetryWorker),
    typeof(McpScanWorker), typeof(ExportWorker), typeof(MaintenanceWorker), typeof(StatusTicker)));
builder.Services.AddSingleton<IHostedService>(sp => new ConditionalWorker(sp, o => o.Demo, typeof(DemoWorker)));

var app = builder.Build();

// Fail fast on a broken data directory or policy, before accepting requests.
app.Services.GetRequiredService<PolicyManager>();
app.Services.GetRequiredService<TokenService>();

app.UseExceptionHandler(errorApp => errorApp.Run(async ctx =>
{
    var ex = ctx.Features.Get<IExceptionHandlerFeature>()?.Error;
    var bad = ex is BadHttpRequestException;
    if (!bad) app.Logger.LogError(ex, "Unhandled error for {Path}.", ctx.Request.Path);
    ctx.Response.StatusCode = bad ? ((BadHttpRequestException)ex!).StatusCode : 500;
    await ctx.Response.WriteAsJsonAsync(new { error = bad ? "The request body is not valid JSON for this endpoint." : "Internal error; see the AgentGuard service log." });
}));
app.UseMiddleware<LocalApiSecurityMiddleware>();

var webRoot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
var dashboardFiles = Directory.Exists(webRoot) ? (IFileProvider)new PhysicalFileProvider(webRoot) : new NullFileProvider();
app.Use(async (ctx, next) =>
{
    if (!ctx.Request.Path.StartsWithSegments("/api") && !ctx.Request.Path.StartsWithSegments("/mcp"))
    {
        ctx.Response.Headers.ContentSecurityPolicy =
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'";
    }
    await next();
});
app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = dashboardFiles });
app.UseStaticFiles(new StaticFileOptions { FileProvider = dashboardFiles });

app.MapAgentGuardApi();
app.MapMcpForwarder();
app.Map("/api/{**rest}", () => Endpoints.Error(404, "Unknown API endpoint."));
app.MapFallback(async ctx =>
{
    var index = dashboardFiles.GetFileInfo("index.html");
    ctx.Response.Headers.CacheControl = "no-cache";
    if (index.Exists)
    {
        ctx.Response.ContentType = "text/html; charset=utf-8";
        await ctx.Response.SendFileAsync(index);
        return;
    }
    ctx.Response.ContentType = "text/html; charset=utf-8";
    await ctx.Response.WriteAsync("<!doctype html><title>AgentGuard</title><p>The AgentGuard service is running, but the dashboard is not built. Run <code>npm run build</code> in <code>src/dashboard</code>.</p>");
});

app.Run();

public partial class Program;

namespace AgentGuard.Service
{
    /// <summary>Starts hosted services only when a condition on the options holds.</summary>
    internal sealed class ConditionalWorker : IHostedService
    {
        private readonly List<IHostedService> _workers = new();

        public ConditionalWorker(IServiceProvider sp, Func<AgentGuardOptions, bool> when, params Type[] types)
        {
            if (!when(sp.GetRequiredService<AgentGuardOptions>())) return;
            foreach (var t in types) _workers.Add((IHostedService)ActivatorUtilities.CreateInstance(sp, t));
        }

        public async Task StartAsync(CancellationToken ct)
        {
            foreach (var w in _workers) await w.StartAsync(ct);
        }

        public async Task StopAsync(CancellationToken ct)
        {
            foreach (var w in Enumerable.Reverse(_workers))
            {
                try { await w.StopAsync(ct); } catch { }
            }
        }
    }

    /// <summary>Accepts friendly flags (<c>--demo</c>, <c>--dev</c>, <c>--data-dir X</c>, <c>--port N</c>, <c>--token T</c>) alongside normal configuration arguments.</summary>
    internal static class ServiceArgs
    {
        public static string[] Normalize(string[] args)
        {
            var result = new List<string>();
            for (var i = 0; i < args.Length; i++)
            {
                string? Next() => i + 1 < args.Length ? args[++i] : null;
                switch (args[i])
                {
                    case "--demo": result.Add("--AgentGuard:Demo=true"); break;
                    case "--dev": result.Add("--AgentGuard:DevMode=true"); break;
                    case "--no-enforcement": result.Add("--AgentGuard:DisableEnforcement=true"); break;
                    case "--data-dir": result.Add($"--AgentGuard:DataDir={Next()}"); break;
                    case "--port": result.Add($"--AgentGuard:Port={Next()}"); break;
                    case "--token": result.Add($"--AgentGuard:Token={Next()}"); break;
                    default: result.Add(args[i]); break;
                }
            }
            return result.ToArray();
        }
    }
}
