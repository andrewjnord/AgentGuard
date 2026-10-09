import { useEffect, useMemo, useRef, useState } from 'react';
import { Bell, CircleCheck, CircleHelp, CircleX, Fingerprint, RefreshCw, ShieldCheck } from 'lucide-react';
import type { ActivityStats, Alert, Capabilities } from '../api/types';
import { ActivityChart, ChartLegend } from '../components/ActivityChart';
import { Empty, ErrorBanner, SeverityBadge, Skeleton } from '../components/ui';
import { ago, errMsg, killSwitchEffect, num, plural, stamp } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { href } from '../lib/router';
import { useApp, useStream } from '../lib/store';

const CAPS: { key: keyof Capabilities; label: string; help: string }[] = [
  { key: 'hooks', label: 'Agent hooks', help: 'Pre-action hooks in agents that support them (Claude Code). Actions can be blocked before they run.' },
  { key: 'mcpProxy', label: 'MCP proxy', help: 'Tool calls to proxied MCP servers pass through AgentGuard and can be blocked or held.' },
  { key: 'firewall', label: 'Firewall', help: 'Per-agent outbound rules in Windows Firewall.' },
  { key: 'processControl', label: 'Process control', help: 'Suspend, resume and terminate agent process trees.' },
  { key: 'etw', label: 'ETW sensor', help: 'Kernel event tracing for file, process and network activity. Detect-only for agents without hooks.' },
];

function StatStrip() {
  const { status } = useApp();
  const c = status?.counts;
  const cells: { label: string; value: number | undefined; sub: string; to: string; tone?: 'ask' | 'block' }[] = [
    { label: 'Active agents', value: c?.activeAgents, sub: c ? `of ${num(c.agents)} discovered` : '', to: href('agents') },
    { label: 'Actions today', value: c?.eventsToday, sub: c ? `${num(c.askedToday)} held for approval` : '', to: href('timeline') },
    { label: 'Blocked today', value: c?.blockedToday, sub: 'by policy or detection', to: href('timeline', { verdict: 'block' }), tone: (c?.blockedToday ?? 0) > 0 ? 'block' : undefined },
    { label: 'Pending approvals', value: c?.pendingApprovals, sub: c?.pendingApprovals ? 'waiting for a decision' : 'nothing waiting', to: href('approvals'), tone: (c?.pendingApprovals ?? 0) > 0 ? 'ask' : undefined },
    { label: 'Open alerts', value: c?.openAlerts, sub: 'not yet acknowledged', to: href('alerts') },
  ];
  return (
    <div className="stat-strip panel">
      {cells.map((x) => (
        <a key={x.label} className={`stat ${x.tone ?? ''}`} href={x.to}>
          <span className="stat-label">{x.label}</span>
          <span className="stat-value">{x.value === undefined ? <Skeleton w={48} h={26} /> : num(x.value)}</span>
          <span className="stat-sub">{x.sub}</span>
        </a>
      ))}
    </div>
  );
}

function Posture() {
  const { status } = useApp();
  if (!status) return null;
  const { mode, counts, killSwitch } = status;
  const sentence = killSwitch.engaged
    ? `Kill switch engaged: ${killSwitchEffect(status.capabilities)}.`
    : mode === 'monitor'
      ? `Watching ${plural(counts.activeAgents, 'active agent')}. Nothing is being blocked in monitor mode.`
      : mode === 'strict'
        ? `Strict enforcement on ${plural(counts.activeAgents, 'active agent')}. Anything the policy does not allow needs approval.`
        : `Enforcing policy on ${plural(counts.activeAgents, 'active agent')}.`;
  return (
    <div className="posture">
      <div className={`posture-mark ${killSwitch.engaged ? 'killed' : mode}`} aria-hidden="true"><ShieldCheck size={22} /></div>
      <div className="stack" style={{ gap: 3 }}>
        <h1>{sentence}</h1>
        <p className="muted">
          {num(counts.proxiedMcpServers)} of {num(counts.mcpServers)} MCP servers proxied · {status.platform === 'windows' ? 'Windows' : status.platform}
          {status.devMode && ' · developer mode'}
        </p>
      </div>
    </div>
  );
}

function TopAgents({ stats }: { stats: ActivityStats | undefined }) {
  const max = Math.max(1, ...(stats?.topAgents.map((a) => a.total) ?? [1]));
  return (
    <section className="panel">
      <div className="panel-head"><h2>Most active agents</h2><span className="sub">24 h</span><a className="right" href={href('agents')}>All agents</a></div>
      <div className="panel-body top-agents">
        {!stats && Array.from({ length: 5 }, (_, i) => <Skeleton key={i} h={28} />)}
        {stats && stats.topAgents.length === 0 && <Empty icon={CircleHelp} title="No agent activity yet">Activity appears here as soon as an agent does something.</Empty>}
        {stats?.topAgents.map((a) => (
          <a key={a.agentId} className="top-agent" href={href('timeline', { agentId: a.agentId })}>
            <span className="row" style={{ justifyContent: 'space-between' }}>
              <span className="truncate strong">{a.agentName}</span>
              <span className="num-cell ink2">{num(a.total)}{a.blocked > 0 && <span className="blocked-count"> · {num(a.blocked)} blocked</span>}</span>
            </span>
            <span className="meter" aria-hidden="true">
              <i className="m-rest" style={{ width: `${((a.total - a.blocked) / max) * 100}%` }} />
              {a.blocked > 0 && <i className="m-block" style={{ width: `${Math.max(1.5, (a.blocked / max) * 100)}%` }} />}
            </span>
          </a>
        ))}
      </div>
    </section>
  );
}

function LatestAlerts() {
  const { api } = useApp();
  const alerts = useAsync(() => api.alerts('open'), [api]);
  useStream((m) => {
    if (m.type !== 'alert') return;
    alerts.setData((list) => {
      const rest = (list ?? []).filter((a) => a.id !== m.data.id);
      return m.data.status === 'open' ? [m.data, ...rest] : rest;
    });
  });
  const items: Alert[] = (alerts.data ?? []).slice(0, 6);
  return (
    <section className="panel">
      <div className="panel-head"><h2>Latest open alerts</h2><a className="right" href={href('alerts')}>All alerts</a></div>
      {alerts.error && <div className="panel-body"><ErrorBanner error={alerts.error} onRetry={alerts.reload} /></div>}
      {!alerts.data && !alerts.error && <div className="panel-body grid" style={{ gap: 12 }}>{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} h={30} />)}</div>}
      {alerts.data && items.length === 0 && <Empty icon={Bell} title="No open alerts">Blocked actions and unusual behaviour raise alerts here.</Empty>}
      {items.length > 0 && (
        <ul className="alert-list">
          {items.map((a) => (
            <li key={a.id}>
              <a href={href('alerts')} className="alert-row">
                <SeverityBadge severity={a.severity} />
                <span className="stack">
                  <span className="truncate strong">{a.title}</span>
                  <span className="truncate path">{a.target}</span>
                </span>
                <span className="muted nowrap" style={{ fontSize: 'var(--fs-xs)' }}>{stamp(a.ts)}</span>
              </a>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Protection() {
  const { api, status, setStatus, toast } = useApp();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  if (!status) return null;
  const verify = async () => {
    setBusy(true); setResult(null);
    try {
      const r = await api.verifyIntegrity();
      setResult(r.ok ? `${num(r.checked)} records verified. The log has not been altered.` : `Chain broken at event #${r.firstBadId}. Records after it may have been altered.`);
      setStatus({ ...status, integrity: { ok: r.ok, lastVerifiedAt: r.verifiedAt } });
      toast(r.ok ? 'Audit log verified' : 'Audit log integrity check failed', r.ok ? 'ok' : 'error');
    } catch (e) { toast(errMsg(e), 'error'); } finally { setBusy(false); }
  };
  const ok = status.integrity.ok;
  return (
    <section className="panel">
      <div className="panel-head"><h2>Protection</h2></div>
      <div className="panel-body grid" style={{ gap: 18 }}>
        <div>
          <div className="section-title">Enforcement capabilities</div>
          <ul className="caps">
            {CAPS.map((c) => {
              const on = status.capabilities[c.key];
              return (
                <li key={c.key} className={on ? 'on' : 'off'} title={c.help}>
                  {on ? <CircleCheck size={15} /> : <CircleX size={15} />}
                  <span>{c.label}</span>
                  <span className="muted cap-state">{on ? 'Available' : 'Unavailable'}</span>
                </li>
              );
            })}
          </ul>
        </div>
        <div className="integrity">
          <div className="row" style={{ alignItems: 'flex-start' }}>
            <span className={`integrity-icon ${ok === true ? 'ok' : ok === false ? 'bad' : ''}`}><Fingerprint size={18} /></span>
            <div className="stack" style={{ flex: 1, gap: 2 }}>
              <span className="strong">{ok === true ? 'Audit log intact' : ok === false ? 'Audit log tampering detected' : 'Audit log not verified yet'}</span>
              <span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>
                Every event is hash-chained to the one before it. Last checked {ago(status.integrity.lastVerifiedAt)}.
              </span>
            </div>
            <button className="btn sm" onClick={verify} disabled={busy}><RefreshCw size={13} className={busy ? 'spin' : ''} />{busy ? 'Verifying…' : 'Verify now'}</button>
          </div>
          {result && <p className={`integrity-result ${ok === false ? 'bad' : ''}`} role="status">{result}</p>}
        </div>
      </div>
    </section>
  );
}

export function Overview() {
  const { api } = useApp();
  const stats = useAsync(() => api.activity(24), [api]);
  // Fold live events into the current hour so the chart keeps moving without polling.
  const pendingRefresh = useRef(0);
  useStream((m) => {
    if (m.type !== 'event') return;
    const e = m.data;
    stats.setData((s) => {
      if (!s || !s.buckets.length) return s;
      const buckets = s.buckets.slice();
      const last = buckets[buckets.length - 1];
      const lastEnd = Date.parse(last.ts) + 3600000;
      if (Date.parse(e.ts) >= lastEnd) { pendingRefresh.current++; return s; }
      buckets[buckets.length - 1] = { ...last, total: last.total + 1, blocked: last.blocked + (e.verdict === 'block' ? 1 : 0), asked: last.asked + (e.verdict === 'ask' ? 1 : 0) };
      const topAgents = s.topAgents.map((a) => a.agentId === e.agentId ? { ...a, total: a.total + 1, blocked: a.blocked + (e.verdict === 'block' ? 1 : 0) } : a)
        .sort((a, b) => b.total - a.total);
      return { buckets, topAgents };
    });
  });
  useEffect(() => {
    const t = window.setInterval(() => { if (pendingRefresh.current) { pendingRefresh.current = 0; stats.reload(); } }, 15000);
    return () => window.clearInterval(t);
  }, [stats]);

  const totals = useMemo(() => (stats.data?.buckets ?? []).reduce((a, b) => ({ total: a.total + b.total, asked: a.asked + b.asked, blocked: a.blocked + b.blocked }), { total: 0, asked: 0, blocked: 0 }), [stats.data]);

  return (
    <div className="page overview">
      <Posture />
      <StatStrip />
      <div className="overview-grid">
        <section className="panel chart-panel">
          <div className="panel-head">
            <h2>Activity</h2><span className="sub">Last 24 hours, per hour</span>
            <div className="right"><ChartLegend totals={totals} /></div>
          </div>
          <div className="panel-body">
            {stats.error && <ErrorBanner error={stats.error} onRetry={stats.reload} />}
            {!stats.data && !stats.error && <Skeleton h={264} />}
            {stats.data && <ActivityChart buckets={stats.data.buckets} height={264} />}
          </div>
        </section>
        <TopAgents stats={stats.data} />
        <LatestAlerts />
        <Protection />
      </div>
    </div>
  );
}
