import { useMemo } from 'react';
import { Hand, History } from 'lucide-react';
import type { Approval } from '../api/types';
import { ApprovalCard } from '../components/ApprovalCard';
import { Empty, ErrorBanner, SkeletonRows } from '../components/ui';
import { actionLabel, stamp } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { useApp, useStream } from '../lib/store';

const DECISION_LABEL: Record<NonNullable<Approval['decision']>, string> = {
  allow_once: 'Allowed once', allow_always: 'Always allowed', deny: 'Denied', timeout: 'Timed out',
};

export default function Approvals() {
  const { api, pending, status } = useApp();
  const history = useAsync(() => api.approvals(), [api]);
  useStream((m) => {
    if (m.type === 'approval' && m.data.status !== 'pending') {
      history.setData((l) => [m.data, ...(l ?? []).filter((a) => a.id !== m.data.id)]);
    }
  });
  const decided = useMemo(() => (history.data ?? []).filter((a) => a.status !== 'pending').slice(0, 200), [history.data]);
  const sorted = useMemo(() => [...pending].sort((a, b) => a.expiresAt.localeCompare(b.expiresAt)), [pending]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Approvals</h1>
          <p className="lede">Actions held by an ask rule wait here for a decision. Unanswered requests are denied when their timer runs out.</p>
        </div>
      </div>

      {sorted.length === 0 ? (
        <section className="panel" style={{ marginBottom: 20 }}>
          <Empty icon={Hand} title="Nothing waiting for approval">
            {status?.mode === 'monitor' ? 'Monitor mode never holds actions. Switch to enforce mode for ask rules to take effect.' : 'When an agent tries something your policy marks as ask, it appears here and in the tray.'}
          </Empty>
        </section>
      ) : (
        <div className="approval-grid">
          {sorted.map((a) => <ApprovalCard key={a.id} approval={a} />)}
        </div>
      )}

      <section className="panel">
        <div className="panel-head"><History size={16} className="muted" /><h2>Decision history</h2></div>
        {history.error && <div className="panel-body"><ErrorBanner error={history.error} onRetry={history.reload} /></div>}
        {!history.data && !history.error && <SkeletonRows rows={5} cols={5} />}
        {history.data && decided.length === 0 && <Empty icon={History} title="No decisions yet">Past approvals and denials are listed here.</Empty>}
        {decided.length > 0 && (
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Requested</th><th>Agent</th><th>Action</th><th>Target</th><th>Decision</th><th>By</th></tr></thead>
              <tbody>
                {decided.map((a) => (
                  <tr key={a.id}>
                    <td className="nowrap num-cell muted">{stamp(a.requestedAt)}</td>
                    <td className="nowrap">{a.agentName}</td>
                    <td className="nowrap">{actionLabel(a.action)}</td>
                    <td style={{ maxWidth: 420 }}><span className="path truncate" style={{ display: 'block' }} title={a.target}>{a.target}</span></td>
                    <td className="nowrap"><span className={`decision ${a.status}`}>{a.decision ? DECISION_LABEL[a.decision] : a.status}</span></td>
                    <td className="muted nowrap">{a.decidedBy ?? 'Policy timeout'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
