using AgentGuard.Core;
using AgentGuard.Core.Policy;
using AgentGuard.Core.Storage;

namespace AgentGuard.Service.Services;

/// <summary>Owns the active policy: loads it, validates and applies changes, and keeps version history.</summary>
public sealed class PolicyManager
{
    private readonly AgentGuardOptions _options;
    private readonly EventStore _store;
    private readonly ILogger<PolicyManager> _log;
    private readonly object _gate = new();
    private PolicyEngine _engine;
    private PolicyVersion _current;

    public event Action<PolicyVersion>? Changed;

    public PolicyManager(AgentGuardOptions options, EventStore store, ILogger<PolicyManager> log)
    {
        _options = options;
        _store = store;
        _log = log;
        SeedDefaults();
        var yaml = File.ReadAllText(options.PolicyPath);
        var parsed = PolicyParser.Parse(yaml, options.DataDir);
        if (!parsed.Ok)
        {
            // A broken policy file must never leave the machine unprotected: fall back to the last good version, then to the default.
            _log.LogError("policy.yaml is invalid ({Error}); falling back to the last applied version.", parsed.Errors[0].Message);
            var last = store.GetPolicy();
            yaml = last?.Yaml ?? File.ReadAllText(DefaultPolicyPath);
            parsed = PolicyParser.Parse(yaml, options.DataDir);
            if (!parsed.Ok)
            {
                yaml = File.ReadAllText(DefaultPolicyPath);
                parsed = PolicyParser.Parse(yaml, options.DataDir);
            }
        }
        _engine = new PolicyEngine(parsed.Document!);
        var stored = store.GetPolicy();
        _current = stored is not null && stored.Yaml == yaml
            ? stored
            : store.SavePolicy(yaml, "system", parsed.Document!.Rules.Count);
    }

    private static string DefaultsDir => Path.Combine(AppContext.BaseDirectory, "defaults", "policies");
    private static string DefaultPolicyPath => Path.Combine(DefaultsDir, "default.yaml");

    private void SeedDefaults()
    {
        Directory.CreateDirectory(_options.DataDir);
        if (!File.Exists(_options.PolicyPath)) File.Copy(DefaultPolicyPath, _options.PolicyPath);
        var allowDir = Path.Combine(_options.DataDir, "allowlists");
        Directory.CreateDirectory(allowDir);
        foreach (var f in Directory.GetFiles(Path.Combine(DefaultsDir, "allowlists")))
        {
            var target = Path.Combine(allowDir, Path.GetFileName(f));
            if (!File.Exists(target)) File.Copy(f, target);
        }
    }

    public PolicyEngine Engine { get { lock (_gate) return _engine; } }
    public PolicyVersion Current { get { lock (_gate) return _current; } }
    public PolicyMode Mode => Engine.Document.Mode;

    public PolicyParser.Result Validate(string yaml) => PolicyParser.Parse(yaml, _options.DataDir);

    public (PolicyVersion? Version, PolicyParser.Result Result) Apply(string yaml, string appliedBy)
    {
        var result = Validate(yaml);
        if (!result.Ok) return (null, result);
        PolicyVersion version;
        lock (_gate)
        {
            File.WriteAllText(_options.PolicyPath + ".tmp", yaml);
            File.Move(_options.PolicyPath + ".tmp", _options.PolicyPath, overwrite: true);
            version = _store.SavePolicy(yaml, appliedBy, result.Document!.Rules.Count);
            _engine = new PolicyEngine(result.Document);
            _current = version;
        }
        _log.LogInformation("Policy v{Version} applied by {By} ({Rules} rules, mode {Mode}).", version.Version, appliedBy, version.RuleCount, result.Document.Mode);
        Changed?.Invoke(version);
        return (version, result);
    }

    public PolicyVersion SetMode(PolicyMode mode, string appliedBy)
    {
        var yaml = PolicyText.SetMode(Current.Yaml, mode);
        var (version, result) = Apply(yaml, appliedBy);
        return version ?? throw new InvalidOperationException(result.Errors[0].Message);
    }

    public string AddAllowRule(string agentId, string action, string target, string decidedBy)
    {
        lock (_gate)
        {
            var (yaml, ruleId) = PolicyText.AddAllowRule(_current.Yaml, agentId, action, target, decidedBy);
            if (yaml != _current.Yaml) Apply(yaml, decidedBy);
            return ruleId;
        }
    }
}
