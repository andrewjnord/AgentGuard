import { useEffect, useMemo, useRef, useState } from 'react';
import { CircleCheck, CircleX, Eye, History, RotateCcw, ShieldCheck, Undo2 } from 'lucide-react';
import { PolicyRejectedError } from '../api/client';
import type { PolicyHistoryEntry, PolicyInfo, PolicyValidation } from '../api/types';
import { YamlEditor, type YamlEditorHandle } from '../components/YamlEditor';
import { Dialog, ErrorBanner, Skeleton } from '../components/ui';
import { ago, errMsg, fullDate, num } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { useRoute } from '../lib/router';
import { useApp } from '../lib/store';

export default function Policy() {
  const { api, toast, status, setStatus } = useApp();
  const route = useRoute();
  const current = useAsync(() => api.policy(), [api]);
  const history = useAsync(() => api.policyHistory(), [api]);
  const [draft, setDraft] = useState<string | null>(null);
  const [validation, setValidation] = useState<PolicyValidation | null>(null);
  const [validatedText, setValidatedText] = useState<string | null>(null);
  const [busy, setBusy] = useState<'validate' | 'apply' | null>(null);
  const [activeLine, setActiveLine] = useState<number | null>(null);
  const [viewing, setViewing] = useState<PolicyInfo | null>(null);
  const [confirmApply, setConfirmApply] = useState(false);
  const editor = useRef<YamlEditorHandle>(null);

  useEffect(() => { if (current.data && draft === null) setDraft(current.data.yaml); }, [current.data, draft]);

  // Jump to a rule when linked from an event (?rule=<id>).
  const rule = route.params.get('rule');
  useEffect(() => {
    if (!rule || draft === null) return;
    const idx = draft.split('\n').findIndex((l) => new RegExp(`^\\s*-?\\s*id:\\s*["']?${rule.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']?\\s*$`).test(l));
    if (idx >= 0) { setActiveLine(idx + 1); requestAnimationFrame(() => editor.current?.goToLine(idx + 1)); }
  }, [rule, draft === null]); // eslint-disable-line react-hooks/exhaustive-deps

  const dirty = draft !== null && current.data !== undefined && draft !== current.data.yaml;
  const stale = validation !== null && validatedText !== draft;
  const errorLines = useMemo(() => new Set((stale ? [] : validation?.errors ?? []).map((e) => e.line).filter((l): l is number => l !== null)), [validation, stale]);

  const validate = async () => {
    if (draft === null) return;
    setBusy('validate');
    try {
      const v = await api.validatePolicy(draft);
      setValidation(v); setValidatedText(draft);
      const first = v.errors.find((e) => e.line !== null);
      if (first?.line) { setActiveLine(first.line); editor.current?.goToLine(first.line); }
    } catch (e) { toast(errMsg(e), 'error'); } finally { setBusy(null); }
  };

  const apply = async () => {
    if (draft === null) return;
    setConfirmApply(false);
    setBusy('apply');
    try {
      const info = await api.applyPolicy(draft);
      current.setData(() => info);
      setDraft(info.yaml);
      setValidation({ ok: true, ruleCount: info.ruleCount, errors: [] }); setValidatedText(info.yaml);
      history.reload();
      if (status && status.mode !== info.mode) setStatus({ ...status, mode: info.mode });
      toast(`Policy version ${info.version} applied (${num(info.ruleCount)} rules)`, 'ok');
    } catch (e) {
      if (e instanceof PolicyRejectedError) {
        setValidation(e.validation); setValidatedText(draft);
        const first = e.validation.errors.find((x) => x.line !== null);
        if (first?.line) { setActiveLine(first.line); editor.current?.goToLine(first.line); }
        toast('The service rejected the policy. Fix the errors and apply again.', 'error');
      } else toast(errMsg(e), 'error');
    } finally { setBusy(null); }
  };

  const view = async (h: PolicyHistoryEntry) => {
    try { setViewing(await api.policyVersion(h.version)); } catch (e) { toast(errMsg(e), 'error'); }
  };

  return (
    <div className="page policy-page">
      <div className="page-head">
        <div>
          <h1>Policy</h1>
          <p className="lede">Rules decide what agents may do: allow, log, ask for approval, or block. The first matching rule wins.</p>
        </div>
        <div className="actions">
          {status && <span className={`mode-pill ${status.mode}`}>Running in {status.mode} mode</span>}
        </div>
      </div>
      {current.error && <ErrorBanner error={current.error} onRetry={current.reload} />}

      <div className="policy-grid">
        <section className="panel editor-panel">
          <div className="panel-head">
            <h2>policy.yaml</h2>
            {current.data && <span className="sub">Version {current.data.version} · applied {ago(current.data.appliedAt)} by {current.data.appliedBy}</span>}
            {dirty && <span className="chip warn">Unapplied changes</span>}
            <div className="right">
              <button className="btn ghost sm" disabled={!dirty || !!busy} onClick={() => { setDraft(current.data!.yaml); setValidation(null); setActiveLine(null); }}><Undo2 size={13} />Discard</button>
              <button className="btn sm" onClick={validate} disabled={draft === null || !!busy}>{busy === 'validate' ? 'Validating…' : 'Validate'}</button>
              <button className="btn primary sm" onClick={() => setConfirmApply(true)} disabled={!dirty || !!busy}><ShieldCheck size={13} />{busy === 'apply' ? 'Applying…' : 'Apply'}</button>
            </div>
          </div>
          {draft === null ? <div className="panel-body"><Skeleton h={480} /></div> : (
            <YamlEditor ref={editor} value={draft} onChange={(v) => { setDraft(v); setActiveLine(null); }} errorLines={errorLines} activeLine={activeLine} label="Policy YAML" />
          )}
          {validation && (
            <div className={`validation ${validation.ok ? 'ok' : 'bad'} ${stale ? 'stale' : ''}`} role="status">
              <div className="row">
                {validation.ok ? <CircleCheck size={16} /> : <CircleX size={16} />}
                <strong>{validation.ok ? `Valid: ${num(validation.ruleCount)} rules` : `${validation.errors.length} ${validation.errors.length === 1 ? 'problem' : 'problems'} found`}</strong>
                {stale && <span className="muted">Edited since last check</span>}
              </div>
              {!validation.ok && (
                <ul className="error-list">
                  {validation.errors.map((e, i) => (
                    <li key={i}>
                      {e.line !== null
                        ? <button className="linkish" onClick={() => { setActiveLine(e.line); editor.current?.goToLine(e.line!); }}>Line {e.line}{e.column !== null ? `:${e.column}` : ''}</button>
                        : <span className="muted">General</span>}
                      <span>{e.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>

        <aside className="panel history-panel">
          <div className="panel-head"><History size={15} className="muted" /><h2>Version history</h2></div>
          {history.error && <div className="panel-body"><ErrorBanner error={history.error} onRetry={history.reload} /></div>}
          {!history.data && !history.error && <div className="panel-body grid" style={{ gap: 10 }}>{Array.from({ length: 3 }, (_, i) => <Skeleton key={i} h={44} />)}</div>}
          <ol className="versions">
            {history.data?.map((h) => (
              <li key={h.version} className={current.data?.version === h.version ? 'current' : ''}>
                <div className="stack">
                  <span className="strong">Version {h.version}{current.data?.version === h.version && <span className="chip on" style={{ marginLeft: 6 }}>Active</span>}</span>
                  <span className="muted" style={{ fontSize: 'var(--fs-xs)' }} title={fullDate(h.appliedAt)}>{ago(h.appliedAt)} · {h.appliedBy} · {num(h.ruleCount)} rules</span>
                </div>
                <button className="btn sm ghost" onClick={() => void view(h)} aria-label={`View version ${h.version}`}><Eye size={13} />View</button>
              </li>
            ))}
          </ol>
        </aside>
      </div>

      {viewing && (
        <Dialog wide title={`Policy version ${viewing.version}`} onClose={() => setViewing(null)}
          footer={<>
            <button className="btn" onClick={() => setViewing(null)}>Close</button>
            <button className="btn primary" onClick={() => { setDraft(viewing.yaml); setValidation(null); setActiveLine(null); setViewing(null); toast(`Version ${viewing.version} loaded into the editor. Apply it to make it active.`, 'info'); }}>
              <RotateCcw size={14} />Restore into editor
            </button>
          </>}>
          <p className="muted" style={{ fontSize: 'var(--fs-sm)' }}>Applied {fullDate(viewing.appliedAt)} by {viewing.appliedBy} · {num(viewing.ruleCount)} rules · {viewing.mode} mode</p>
          <div style={{ height: 420, display: 'flex' }}><YamlEditor value={viewing.yaml} onChange={() => undefined} readOnly label={`Policy version ${viewing.version}`} /></div>
        </Dialog>
      )}
      {confirmApply && (
        <Dialog title="Apply this policy?" onClose={() => setConfirmApply(false)}
          footer={<><button className="btn" onClick={() => setConfirmApply(false)} data-autofocus>Cancel</button><button className="btn primary" onClick={() => void apply()}><ShieldCheck size={14} />Apply policy</button></>}>
          <p className="ink2">The new rules take effect immediately for every agent on this PC. The current version stays in the history so you can restore it.</p>
          {stale || !validation ? <p className="muted" style={{ fontSize: 'var(--fs-sm)' }}>The service validates the policy again before applying it.</p> : null}
        </Dialog>
      )}
    </div>
  );
}
