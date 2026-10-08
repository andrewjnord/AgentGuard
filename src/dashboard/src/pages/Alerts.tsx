import { useState } from 'react';
import { Bell, Check, CheckCheck, RotateCcw } from 'lucide-react';
import type { Alert, AlertStatus } from '../api/types';
import { Empty, ErrorBanner, SeverityBadge, SkeletonRows } from '../components/ui';
import { actionLabel, errMsg, num, stamp } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { href } from '../lib/router';
import { useApp, useStream } from '../lib/store';

const TABS: { id: AlertStatus | 'all'; label: string }[] = [
  { id: 'open', label: 'Open' }, { id: 'acked', label: 'Acknowledged' }, { id: 'closed', label: 'Closed' }, { id: 'all', label: 'All' },
];

export default function Alerts() {
  const { api, toast, status, setStatus } = useApp();
  const [tab, setTab] = useState<AlertStatus | 'all'>('open');
  const alerts = useAsync(() => api.alerts(tab === 'all' ? undefined : tab), [api, tab]);
  const [busy, setBusy] = useState<Set<number>>(new Set());

  useStream((m) => {
    if (m.type !== 'alert') return;
    alerts.setData((l) => {
      const rest = (l ?? []).filter((a) => a.id !== m.data.id);
      return tab === 'all' || m.data.status === tab ? [m.data, ...rest] : rest;
    });
  });

  const update = async (a: Alert, s: AlertStatus) => {
    setBusy((b) => new Set(b).add(a.id));
    try {
      const u = await api.setAlertStatus(a.id, s);
      alerts.setData((l) => (tab === 'all' ? l?.map((x) => (x.id === u.id ? u : x)) : l?.filter((x) => x.id !== u.id)));
      if (status && a.status === 'open' && s !== 'open') setStatus({ ...status, counts: { ...status.counts, openAlerts: Math.max(0, status.counts.openAlerts - 1) } });
      toast(s === 'acked' ? 'Alert acknowledged' : s === 'closed' ? 'Alert closed' : 'Alert reopened', 'ok');
    } catch (e) { toast(errMsg(e), 'error'); } finally { setBusy((b) => { const n = new Set(b); n.delete(a.id); return n; }); }
  };

  const list = alerts.data ?? [];
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <p className="lede">Blocked actions, detections that could not be prevented, and newly discovered agents.</p>
        </div>
      </div>
      <section className="panel">
        <div className="toolbar">
          <div className="segmented small" role="tablist" aria-label="Alert status">
            {TABS.map((t) => (
              <button key={t.id} role="tab" aria-selected={tab === t.id} aria-checked={tab === t.id} onClick={() => setTab(t.id)}>
                {t.label}{t.id === 'open' && status ? <span className="muted num-cell"> {num(status.counts.openAlerts)}</span> : null}
              </button>
            ))}
          </div>
        </div>
        {alerts.error && <div className="panel-body"><ErrorBanner error={alerts.error} onRetry={alerts.reload} /></div>}
        {alerts.loading && !alerts.data && <SkeletonRows rows={8} cols={5} />}
        {alerts.data && list.length === 0 && (
          <Empty icon={Bell} title={tab === 'open' ? 'No open alerts' : 'No alerts here'}>
            {tab === 'open' ? 'Everything has been triaged. New alerts appear here as soon as they are raised.' : 'Alerts move here as you acknowledge or close them.'}
          </Empty>
        )}
        {list.length > 0 && (
          <ul className="alerts-full">
            {list.map((a) => (
              <li key={a.id} className={`alert-item s-${a.severity} st-${a.status}`}>
                <SeverityBadge severity={a.severity} />
                <div className="stack" style={{ gap: 3 }}>
                  <span className="strong">{a.title}</span>
                  <span className="path truncate" title={a.target}>{a.target}</span>
                  <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>
                    {a.agentName} · {actionLabel(a.action)}{a.ruleId && <> · <code>{a.ruleId}</code></>} · <a href={href('timeline', { agentId: a.agentId, q: a.target.slice(0, 80) })}>Show event</a>
                  </span>
                </div>
                <span className="muted nowrap num-cell" style={{ fontSize: 'var(--fs-xs)' }}>{stamp(a.ts)}</span>
                <span className="row alert-actions">
                  {a.status === 'open' && <button className="btn sm" disabled={busy.has(a.id)} onClick={() => update(a, 'acked')}><Check size={13} />Acknowledge</button>}
                  {a.status !== 'closed' && <button className="btn sm" disabled={busy.has(a.id)} onClick={() => update(a, 'closed')}><CheckCheck size={13} />Close</button>}
                  {a.status !== 'open' && <button className="btn sm ghost" disabled={busy.has(a.id)} onClick={() => update(a, 'open')}><RotateCcw size={13} />Reopen</button>}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
