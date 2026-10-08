import { useState } from 'react';
import { Check, CheckCheck, Clock, Ban } from 'lucide-react';
import type { Approval, ApprovalDecision } from '../api/types';
import { actionLabel, countdown, errMsg, stamp } from '../lib/format';
import { useNow } from '../lib/hooks';
import { useApp } from '../lib/store';
import { href } from '../lib/router';

export function Countdown({ expiresAt, requestedAt }: { expiresAt: string; requestedAt: string }) {
  const now = useNow(500);
  const total = Math.max(1, Date.parse(expiresAt) - Date.parse(requestedAt));
  const left = Math.max(0, Date.parse(expiresAt) - now);
  const frac = left / total;
  const urgent = left < 20000;
  return (
    <div className={`countdown ${urgent ? 'urgent' : ''}`} role="timer" aria-label={`${Math.ceil(left / 1000)} seconds left`}>
      <Clock size={13} aria-hidden="true" />
      <span className="num-cell">{countdown(left)}</span>
      <span className="countdown-bar" aria-hidden="true"><i style={{ transform: `scaleX(${frac})` }} /></span>
    </div>
  );
}

export function ApprovalCard({ approval, compact, onDecided }: { approval: Approval; compact?: boolean; onDecided?: (a: Approval) => void }) {
  const { api, toast, refreshPending } = useApp();
  const [busy, setBusy] = useState<ApprovalDecision | null>(null);
  const decide = async (d: ApprovalDecision) => {
    setBusy(d);
    try {
      const res = await api.decide(approval.id, d);
      toast(d === 'deny' ? `Denied ${approval.agentName}` : d === 'allow_always' ? `Always allowing this for ${approval.agentName}` : `Allowed once for ${approval.agentName}`, 'ok');
      onDecided?.(res);
    } catch (e) {
      toast(errMsg(e), 'error');
      refreshPending();
    } finally { setBusy(null); }
  };
  const reason = typeof approval.details.reason === 'string' ? approval.details.reason : null;
  const cwd = typeof approval.details.cwd === 'string' ? approval.details.cwd : null;
  return (
    <article className={`approval ${compact ? 'compact' : ''}`} aria-label={`Approval request from ${approval.agentName}`}>
      <header className="approval-head">
        <div className="stack">
          <span className="approval-who"><strong>{approval.agentName}</strong> <span className="muted">is asking to perform a</span> <strong>{actionLabel(approval.action)}</strong></span>
          <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>
            Requested {stamp(approval.requestedAt)}{approval.ruleId && <> by rule <code>{approval.ruleId}</code></>}
          </span>
        </div>
        <Countdown expiresAt={approval.expiresAt} requestedAt={approval.requestedAt} />
      </header>
      <pre className="approval-target">{approval.target}</pre>
      {(reason || cwd) && !compact && (
        <dl className="kv" style={{ fontSize: 'var(--fs-xs)' }}>
          {cwd && (<><dt>Working directory</dt><dd className="path">{cwd}</dd></>)}
          {reason && (<><dt>Why it was held</dt><dd>{reason}</dd></>)}
        </dl>
      )}
      <footer className="approval-actions">
        <button className="btn danger-outline" onClick={() => decide('deny')} disabled={!!busy} data-autofocus>
          <Ban size={14} />{busy === 'deny' ? 'Denying…' : 'Deny'}
        </button>
        <span style={{ flex: 1 }} />
        <button className="btn" onClick={() => decide('allow_always')} disabled={!!busy} title="Allow now and add a rule so this is not asked again">
          <CheckCheck size={14} />{busy === 'allow_always' ? 'Saving…' : 'Always allow'}
        </button>
        <button className="btn primary" onClick={() => decide('allow_once')} disabled={!!busy}>
          <Check size={14} />{busy === 'allow_once' ? 'Allowing…' : 'Allow once'}
        </button>
      </footer>
      {!compact && <a className="approval-link" href={href('timeline', { agentId: approval.agentId })}>Show {approval.agentName} activity</a>}
    </article>
  );
}
