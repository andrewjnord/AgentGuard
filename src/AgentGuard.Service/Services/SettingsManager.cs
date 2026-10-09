using AgentGuard.Core;
using AgentGuard.Core.Storage;

namespace AgentGuard.Service.Services;

public sealed class SettingsManager
{
    private const string Key = "settings";
    private readonly EventStore _store;
    private readonly object _gate = new();
    private AgentGuardSettings _settings;
    private Redactor _redactor;

    public event Action<AgentGuardSettings>? Changed;

    public SettingsManager(EventStore store)
    {
        _store = store;
        var json = store.GetSetting(Key);
        _settings = (json is null ? null : Json.Deserialize<AgentGuardSettings>(json)) ?? new AgentGuardSettings();
        _redactor = new Redactor(_settings.Redaction.Patterns);
    }

    public AgentGuardSettings Current { get { lock (_gate) return _settings; } }
    public Redactor Redactor { get { lock (_gate) return _redactor; } }

    /// <summary>Validates and saves settings. A masked Splunk token keeps the stored one; an empty token clears it.</summary>
    public (AgentGuardSettings? Saved, List<string> Errors) Update(AgentGuardSettings incoming)
    {
        lock (_gate)
        {
            if (incoming.Exports.Splunk.Token == AgentGuardSettings.MaskedSecret)
                incoming.Exports.Splunk.Token = _settings.Exports.Splunk.Token;
            else if (string.IsNullOrEmpty(incoming.Exports.Splunk.Token))
                incoming.Exports.Splunk.Token = null;
            var errors = incoming.Validate().ToList();
            if (errors.Count > 0) return (null, errors);
            _settings = incoming;
            _redactor = new Redactor(incoming.Redaction.Patterns);
            _store.SetSetting(Key, Json.Serialize(incoming));
        }
        Changed?.Invoke(incoming);
        return (incoming, new List<string>());
    }
}
