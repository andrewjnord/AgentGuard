import { useEffect, useState, type ReactNode } from 'react';
import { CircleCheck, CircleX, Plus, Send, Trash2 } from 'lucide-react';
import type { ExportTarget, Settings as SettingsT } from '../api/types';
import { MASKED_TOKEN } from '../api/types';
import { ErrorBanner, Skeleton, Switch } from '../components/ui';
import { errMsg } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { useApp } from '../lib/store';

function Section({ title, description, children, aside }: { title: string; description?: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="settings-section">
      <div className="settings-intro">
        <h2>{title}</h2>
        {description && <p className="muted">{description}</p>}
        {aside}
      </div>
      <div className="panel panel-body settings-fields">{children}</div>
    </section>
  );
}

function TestButton({ target, dirty }: { target: ExportTarget; dirty: boolean }) {
  const { api } = useApp();
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<{ ok: boolean; message: string } | null>(null);
  const run = async () => {
    setBusy(true); setRes(null);
    try { setRes(await api.testExport(target)); } catch (e) { setRes({ ok: false, message: errMsg(e) }); } finally { setBusy(false); }
  };
  return (
    <div className="test-export">
      <button className="btn sm" onClick={run} disabled={busy} title={dirty ? 'Tests use the saved settings. Save first to test your changes.' : undefined}>
        <Send size={13} />{busy ? 'Sending…' : 'Send test event'}
      </button>
      {dirty && !res && <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>Uses saved settings</span>}
      {res && <span className={`test-result ${res.ok ? 'ok' : 'bad'}`} role="status">{res.ok ? <CircleCheck size={14} /> : <CircleX size={14} />}{res.message}</span>}
    </div>
  );
}

export default function SettingsPage() {
  const { api, toast } = useApp();
  const saved = useAsync(() => api.settings(), [api]);
  const [s, setS] = useState<SettingsT | null>(null);
  const [saving, setSaving] = useState(false);
  const [newPattern, setNewPattern] = useState('');
  const [patternError, setPatternError] = useState<string | null>(null);

  useEffect(() => { if (saved.data && !s) setS(structuredClone(saved.data)); }, [saved.data, s]);
  const dirty = !!s && !!saved.data && JSON.stringify(s) !== JSON.stringify(saved.data);
  const exportsDirty = (k: ExportTarget) => !!s && !!saved.data && JSON.stringify(s.exports[k]) !== JSON.stringify(saved.data.exports[k]);

  useEffect(() => {
    if (!dirty) return;
    const on = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener('beforeunload', on);
    return () => window.removeEventListener('beforeunload', on);
  }, [dirty]);

  if (saved.error && !s) return <div className="page"><ErrorBanner error={saved.error} onRetry={saved.reload} /></div>;
  if (!s) return <div className="page"><Skeleton w={200} h={24} /><Skeleton h={300} style={{ marginTop: 24 }} /></div>;

  const up = (fn: (d: SettingsT) => void) => setS((prev) => { const d = structuredClone(prev!); fn(d); return d; });
  const save = async () => {
    setSaving(true);
    try { const r = await api.saveSettings(s); saved.setData(() => r); setS(structuredClone(r)); toast('Settings saved', 'ok'); }
    catch (e) { toast(errMsg(e), 'error'); } finally { setSaving(false); }
  };
  const addPattern = () => {
    const p = newPattern.trim(); if (!p) return;
    try { new RegExp(p.replace(/^\(\?i\)/, '')); } catch { setPatternError('This is not a valid regular expression.'); return; }
    if (s.redaction.patterns.includes(p)) { setPatternError('That pattern is already in the list.'); return; }
    up((d) => { d.redaction.patterns.push(p); }); setNewPattern(''); setPatternError(null);
  };
  const sp = s.exports.splunk; const sl = s.exports.syslog; const jf = s.exports.jsonFile;

  return (
    <div className="page settings-page">
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="lede">How AgentGuard stores events, handles failures and forwards events to your SIEM.</p>
        </div>
      </div>

      <Section title="Protection" description="What happens when AgentGuard cannot make a decision, and how long it waits for one.">
        <div className="field">
          <span className="label" id="failmode">If the policy engine is unavailable</span>
          <div className="segmented" role="radiogroup" aria-labelledby="failmode">
            <button role="radio" aria-checked={s.failMode === 'closed'} onClick={() => up((d) => { d.failMode = 'closed'; })}>Block actions (fail closed)</button>
            <button role="radio" aria-checked={s.failMode === 'open'} onClick={() => up((d) => { d.failMode = 'open'; })}>Allow actions (fail open)</button>
          </div>
          <span className="hint">Fail closed is safer but can stall agents if the service is restarting.</span>
        </div>
        <div className="field">
          <label htmlFor="timeout">Approval timeout</label>
          <div className="row"><input id="timeout" className="input num-cell" style={{ width: 100 }} type="number" min={10} max={3600} value={s.approvalTimeoutSeconds} onChange={(e) => up((d) => { d.approvalTimeoutSeconds = Math.max(10, Number(e.target.value) || 0); })} /><span className="muted">seconds, then the request is denied</span></div>
        </div>
        <div className="field">
          <Switch checked={s.autoSuspendOnDetectBlock} onChange={(v) => up((d) => { d.autoSuspendOnDetectBlock = v; })} label="Suspend an agent when a block rule matches an action that could only be detected" />
          <span className="hint" style={{ paddingLeft: 43 }}>For agents without hooks, a blocked file read is observed after the fact. Suspending stops the agent from using what it read.</span>
        </div>
      </Section>

      <Section title="Storage" description="Events are kept in a local, hash-chained audit log.">
        <div className="field">
          <label htmlFor="retention">Keep events for</label>
          <div className="row"><input id="retention" className="input num-cell" style={{ width: 100 }} type="number" min={1} max={3650} value={s.retentionDays} onChange={(e) => up((d) => { d.retentionDays = Math.max(1, Number(e.target.value) || 0); })} /><span className="muted">days</span></div>
        </div>
      </Section>

      <Section title="Splunk HTTP Event Collector" description="Send every event to Splunk as OCSF JSON." aside={<Switch checked={sp.enabled} onChange={(v) => up((d) => { d.exports.splunk.enabled = v; })} label="Enabled" />}>
        <fieldset disabled={!sp.enabled} className="fields-grid">
          <div className="field span-2"><label htmlFor="hec-url">HEC URL</label><input id="hec-url" className="input mono" value={sp.url} placeholder="https://splunk.example.com:8088/services/collector/event" onChange={(e) => up((d) => { d.exports.splunk.url = e.target.value; })} /></div>
          <div className="field span-2">
            <label htmlFor="hec-token">HEC token</label>
            <input id="hec-token" className="input mono" type="password" autoComplete="off" value={sp.token ?? ''} placeholder={sp.token === null ? 'Not set' : ''}
              onFocus={(e) => { if (sp.token === MASKED_TOKEN) e.currentTarget.select(); }}
              onChange={(e) => up((d) => { d.exports.splunk.token = e.target.value === '' ? null : e.target.value; })} />
            <span className="hint">{sp.token === MASKED_TOKEN ? 'A token is stored. Leave this as is to keep it, or type a new one.' : 'Stored encrypted on this PC.'}</span>
          </div>
          <div className="field"><label htmlFor="hec-index">Index</label><input id="hec-index" className="input mono" value={sp.index} onChange={(e) => up((d) => { d.exports.splunk.index = e.target.value; })} /></div>
          <div className="field"><label htmlFor="hec-st">Sourcetype</label><input id="hec-st" className="input mono" value={sp.sourcetype} onChange={(e) => up((d) => { d.exports.splunk.sourcetype = e.target.value; })} /></div>
          <div className="field span-2"><Switch checked={sp.verifyTls} onChange={(v) => up((d) => { d.exports.splunk.verifyTls = v; })} label="Verify the TLS certificate" disabled={!sp.enabled} /></div>
        </fieldset>
        <TestButton target="splunk" dirty={exportsDirty('splunk')} />
      </Section>

      <Section title="Syslog" description="Send CEF-formatted events to a syslog collector." aside={<Switch checked={sl.enabled} onChange={(v) => up((d) => { d.exports.syslog.enabled = v; })} label="Enabled" />}>
        <fieldset disabled={!sl.enabled} className="fields-grid">
          <div className="field span-2"><label htmlFor="sl-host">Host</label><input id="sl-host" className="input mono" value={sl.host} onChange={(e) => up((d) => { d.exports.syslog.host = e.target.value; })} /></div>
          <div className="field"><label htmlFor="sl-port">Port</label><input id="sl-port" className="input num-cell" type="number" min={1} max={65535} value={sl.port} onChange={(e) => up((d) => { d.exports.syslog.port = Number(e.target.value) || 0; })} /></div>
          <div className="field"><label htmlFor="sl-proto">Protocol</label>
            <select id="sl-proto" className="select" value={sl.protocol} onChange={(e) => up((d) => { d.exports.syslog.protocol = e.target.value as 'udp' | 'tcp'; })}><option value="tcp">TCP</option><option value="udp">UDP</option></select>
          </div>
        </fieldset>
        <TestButton target="syslog" dirty={exportsDirty('syslog')} />
      </Section>

      <Section title="JSON file" description="Write events as NDJSON files that a forwarder can pick up." aside={<Switch checked={jf.enabled} onChange={(v) => up((d) => { d.exports.jsonFile.enabled = v; })} label="Enabled" />}>
        <fieldset disabled={!jf.enabled} className="fields-grid">
          <div className="field span-2"><label htmlFor="jf-dir">Directory</label><input id="jf-dir" className="input mono" value={jf.directory} onChange={(e) => up((d) => { d.exports.jsonFile.directory = e.target.value; })} /></div>
        </fieldset>
        <TestButton target="jsonFile" dirty={exportsDirty('jsonFile')} />
      </Section>

      <Section title="Redaction" description="Text matching these regular expressions is replaced with [REDACTED] before events are stored or exported.">
        <ul className="patterns">
          {s.redaction.patterns.length === 0 && <li className="muted">No redaction patterns. Secrets in commands and tool arguments are stored as-is.</li>}
          {s.redaction.patterns.map((p, i) => (
            <li key={`${p}-${i}`}><code>{p}</code><button className="btn ghost sm icon" aria-label={`Remove pattern ${p}`} onClick={() => up((d) => { d.redaction.patterns.splice(i, 1); })}><Trash2 size={13} /></button></li>
          ))}
        </ul>
        <form className="row" onSubmit={(e) => { e.preventDefault(); addPattern(); }}>
          <input className="input mono" style={{ flex: 1 }} placeholder="e.g. sk-[A-Za-z0-9]{32,}" value={newPattern} onChange={(e) => { setNewPattern(e.target.value); setPatternError(null); }} aria-label="New redaction pattern" aria-invalid={!!patternError} />
          <button className="btn" type="submit" disabled={!newPattern.trim()}><Plus size={14} />Add pattern</button>
        </form>
        {patternError && <span className="field-error" role="alert">{patternError}</span>}
      </Section>

      <div className={`save-bar ${dirty ? 'dirty' : ''}`}>
        <span className={dirty ? 'ink2' : 'muted'}>{dirty ? 'You have unsaved changes.' : 'All changes saved.'}</span>
        <button className="btn ghost" disabled={!dirty || saving} onClick={() => setS(structuredClone(saved.data!))}>Discard</button>
        <button className="btn primary" disabled={!dirty || saving} onClick={save}>{saving ? 'Saving…' : 'Save settings'}</button>
      </div>
    </div>
  );
}
