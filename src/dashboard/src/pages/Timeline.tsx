import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Download, Pause, Play, Search, X } from 'lucide-react';
import type { Agent, AgentEvent, EventQuery, ExportFormat } from '../api/types';
import { EVENT_SOURCES, KNOWN_ACTIONS, SEVERITIES, VERDICTS } from '../api/types';
import { Dialog, Drawer, Empty, ErrorBanner, JsonView, SeverityBadge, SkeletonRows, VerdictBadge } from '../components/ui';
import { SOURCE_LABELS, actionLabel, errMsg, fullDate, num, stamp } from '../lib/format';
import { useDebounced } from '../lib/hooks';
import { href, useRoute } from '../lib/router';
import { useApp, useStream } from '../lib/store';

const RANGES = [
  { id: '1h', label: 'Last hour', ms: 3600000 },
  { id: '24h', label: 'Last 24 hours', ms: 86400000 },
  { id: '7d', label: 'Last 7 days', ms: 7 * 86400000 },
  { id: 'all', label: 'All retained', ms: 0 },
] as const;
type RangeId = (typeof RANGES)[number]['id'];

interface Filters { agentId: string; action: string; verdict: string; severity: string; source: string; q: string; range: RangeId }
const FILTER_KEYS: (keyof Filters)[] = ['agentId', 'action', 'verdict', 'severity', 'source', 'q', 'range'];
const MAX_ROWS = 3000;
const PAGE = 100;

function fromParams(p: URLSearchParams): Filters {
  const range = p.get('range');
  return {
    agentId: p.get('agentId') ?? '', action: p.get('action') ?? '', verdict: p.get('verdict') ?? '', severity: p.get('severity') ?? '',
    source: p.get('source') ?? '', q: p.get('q') ?? '', range: RANGES.some((r) => r.id === range) ? (range as RangeId) : '24h',
  };
}

function matches(e: AgentEvent, f: Filters): boolean {
  if (f.agentId && e.agentId !== f.agentId) return false;
  if (f.action && e.action !== f.action) return false;
  if (f.verdict && e.verdict !== f.verdict) return false;
  if (f.severity && e.severity !== f.severity) return false;
  if (f.source && e.source !== f.source) return false;
  if (f.q) {
    const t = f.q.toLowerCase();
    if (!`${e.target} ${e.agentName} ${e.action} ${e.ruleId ?? ''}`.toLowerCase().includes(t)) return false;
  }
  return true;
}

function EventDrawer({ event, onClose }: { event: AgentEvent; onClose: () => void }) {
  const { toast } = useApp();
  const copy = (text: string) => { void navigator.clipboard?.writeText(text).then(() => toast('Copied', 'ok'), () => undefined); };
  return (
    <Drawer onClose={onClose} title={actionLabel(event.action)}
      subtitle={<span>{event.agentName} · event #{event.id} · {fullDate(event.ts)}</span>}
      footer={<>
        <a className="btn" href={href('timeline', { agentId: event.agentId })} onClick={onClose}>More from {event.agentName}</a>
        <button className="btn ghost" onClick={() => copy(JSON.stringify(event, null, 2))}>Copy as JSON</button>
      </>}>
      <div className={`verdict-callout ${event.verdict}`}>
        <VerdictBadge verdict={event.verdict} />
        <span>
          {event.verdict === 'block' && (event.enforced ? 'Blocked before it ran.' : 'Matched a block rule, but was only detected. The action was not prevented.')}
          {event.verdict === 'ask' && (event.enforced ? 'Held for approval.' : 'Matched an ask rule but was not held (monitor mode or detect-only).')}
          {event.verdict === 'log' && 'Allowed and recorded.'}
          {event.verdict === 'allow' && 'Allowed.'}
        </span>
      </div>
      <section>
        <div className="section-title">Target</div>
        <pre className="approval-target">{event.target}</pre>
      </section>
      <dl className="kv">
        <dt>Agent</dt><dd><a href={href('agents', { id: event.agentId })} onClick={onClose}>{event.agentName}</a> <span className="muted mono">{event.agentId}</span></dd>
        <dt>Process</dt><dd className="mono">{event.pid ?? '–'}</dd>
        <dt>Severity</dt><dd><SeverityBadge severity={event.severity} /></dd>
        <dt>Rule</dt><dd>{event.ruleId ? <a href={href('policy', { rule: event.ruleId })} onClick={onClose}><code>{event.ruleId}</code></a> : <span className="muted">No rule matched (default)</span>}</dd>
        <dt>Enforced</dt><dd>{event.enforced ? 'Yes, the verdict was applied' : 'No, observed only'}</dd>
        <dt>Source</dt><dd>{SOURCE_LABELS[event.source] ?? event.source}</dd>
        <dt>Chain hash</dt><dd><code className="hash" title="Click to copy" onClick={() => copy(event.hash)}>{event.hash}</code></dd>
      </dl>
      <section>
        <div className="section-title">Details</div>
        <JsonView value={event.details} />
      </section>
    </Drawer>
  );
}

function ExportDialog({ filters, agents, onClose }: { filters: Filters; agents: Agent[]; onClose: () => void }) {
  const { api, toast } = useApp();
  const [format, setFormat] = useState<ExportFormat>('ocsf');
  const [busy, setBusy] = useState(false);
  const range = RANGES.find((r) => r.id === filters.range)!;
  const go = async () => {
    setBusy(true);
    try {
      await api.download({ format, agentId: filters.agentId || undefined, from: range.ms ? new Date(Date.now() - range.ms).toISOString() : undefined });
      toast('Export started', 'ok'); onClose();
    } catch (e) { toast(errMsg(e), 'error'); } finally { setBusy(false); }
  };
  const agentName = agents.find((a) => a.id === filters.agentId)?.name;
  return (
    <Dialog title="Export events" onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={go} disabled={busy}><Download size={14} />{busy ? 'Preparing…' : 'Download'}</button></>}>
      <p className="ink2">Exports {range.label.toLowerCase()}{agentName ? ` for ${agentName}` : ' for all agents'}. Other timeline filters are not applied to exports.</p>
      <div className="format-options" role="radiogroup" aria-label="Format">
        {([['ocsf', 'OCSF', 'NDJSON in the Open Cybersecurity Schema Framework. Best for Splunk and modern SIEMs.'],
          ['cef', 'CEF', 'ArcSight Common Event Format, one line per event.'],
          ['json', 'AgentGuard JSON', 'Raw events as NDJSON, exactly as stored.']] as const).map(([id, label, help]) => (
          <label key={id} className={`format-option ${format === id ? 'on' : ''}`}>
            <input type="radio" name="fmt" checked={format === id} onChange={() => setFormat(id)} />
            <span className="stack"><span className="strong">{label}</span><span className="muted" style={{ fontSize: 'var(--fs-xs)' }}>{help}</span></span>
          </label>
        ))}
      </div>
    </Dialog>
  );
}

export default function Timeline() {
  const { api } = useApp();
  const route = useRoute();
  const [filters, setFilters] = useState<Filters>(() => fromParams(route.params));
  const [qInput, setQInput] = useState(filters.q);
  const q = useDebounced(qInput, 300);
  const [items, setItems] = useState<AgentEvent[]>([]);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const [buffer, setBuffer] = useState<AgentEvent[]>([]);
  const [selected, setSelected] = useState<AgentEvent | null>(null);
  const [exporting, setExporting] = useState(false);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [fresh, setFresh] = useState<Set<number>>(new Set());
  const sentinel = useRef<HTMLDivElement>(null);
  const reqId = useRef(0);

  useEffect(() => { api.agents().then(setAgents).catch(() => undefined); }, [api]);
  useEffect(() => { setFilters((f) => (f.q === q ? f : { ...f, q })); }, [q]);
  // Follow external navigation (e.g. "View activity" links) to this page with new params.
  useEffect(() => {
    const next = fromParams(route.params);
    setFilters((f) => (JSON.stringify(f) === JSON.stringify(next) ? f : next));
    setQInput(next.q);
  }, [route.params.toString()]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reflect filters in the URL so views can be shared and survive reload.
  useEffect(() => {
    const sp = new URLSearchParams();
    for (const k of FILTER_KEYS) if (filters[k] && !(k === 'range' && filters[k] === '24h')) sp.set(k, filters[k]);
    const s = sp.toString();
    const target = `#/timeline${s ? `?${s}` : ''}`;
    if (window.location.hash !== target) window.history.replaceState(window.history.state, '', target);
  }, [filters]);

  const query = useCallback((before?: number): EventQuery => {
    const range = RANGES.find((r) => r.id === filters.range)!;
    return {
      agentId: filters.agentId || undefined, action: filters.action || undefined, verdict: filters.verdict || undefined,
      severity: filters.severity || undefined, source: filters.source || undefined, q: filters.q || undefined,
      from: range.ms ? new Date(Date.now() - range.ms).toISOString() : undefined, before, limit: PAGE,
    };
  }, [filters]);

  useEffect(() => {
    const id = ++reqId.current;
    setLoading(true); setError(null); setBuffer([]);
    api.events(query()).then((p) => {
      if (id !== reqId.current) return;
      setItems(p.items); setNextBefore(p.nextBefore);
    }).catch((e: unknown) => { if (id === reqId.current) setError(errMsg(e)); })
      .finally(() => { if (id === reqId.current) setLoading(false); });
  }, [api, query]);

  const loadMore = useCallback(async () => {
    if (loadingMore || nextBefore === null || items.length >= MAX_ROWS) return;
    setLoadingMore(true);
    const id = reqId.current;
    try {
      const p = await api.events(query(nextBefore));
      if (id !== reqId.current) return;
      setItems((l) => { const seen = new Set(l.map((e) => e.id)); return [...l, ...p.items.filter((e) => !seen.has(e.id))]; });
      setNextBefore(p.nextBefore);
    } catch (e) { setError(errMsg(e)); } finally { setLoadingMore(false); }
  }, [api, query, nextBefore, loadingMore, items.length]);

  useEffect(() => {
    const el = sentinel.current; if (!el) return;
    const io = new IntersectionObserver((entries) => { if (entries[0].isIntersecting) void loadMore(); }, { rootMargin: '400px' });
    io.observe(el);
    return () => io.disconnect();
  }, [loadMore]);

  useStream((m) => {
    if (m.type !== 'event' || loading) return;
    if (!matches(m.data, filters)) return;
    if (paused) { setBuffer((b) => [m.data, ...b].slice(0, 500)); return; }
    setItems((l) => (l.some((e) => e.id === m.data.id) ? l : [m.data, ...l].slice(0, MAX_ROWS)));
    setFresh((s) => new Set(s).add(m.data.id));
    window.setTimeout(() => setFresh((s) => { const n = new Set(s); n.delete(m.data.id); return n; }), 1600);
  });

  const resume = () => {
    setItems((l) => { const seen = new Set(l.map((e) => e.id)); return [...buffer.filter((e) => !seen.has(e.id)), ...l].slice(0, MAX_ROWS); });
    setBuffer([]); setPaused(false);
  };

  const set = (k: keyof Filters, v: string) => setFilters((f) => ({ ...f, [k]: v }));
  const activeCount = (['agentId', 'action', 'verdict', 'severity', 'source', 'q'] as const).filter((k) => filters[k]).length;
  const agentOptions = useMemo(() => [...agents].sort((a, b) => a.name.localeCompare(b.name)), [agents]);

  return (
    <div className="page timeline-page">
      <div className="page-head">
        <div>
          <h1>Timeline</h1>
          <p className="lede">Every action taken by every agent, newest first.</p>
        </div>
        <div className="actions">
          {paused
            ? <button className="btn" onClick={resume}><Play size={14} />Resume live{buffer.length > 0 && <span className="chip warn">{num(buffer.length)} new</span>}</button>
            : <button className="btn" onClick={() => setPaused(true)}><Pause size={14} />Pause live</button>}
          <button className="btn" onClick={() => setExporting(true)}><Download size={14} />Export</button>
        </div>
      </div>

      <section className="panel timeline-panel">
        <div className="filters" role="search">
          <div className="input-icon filter-q">
            <Search size={14} />
            <input className="input" placeholder="Search target, agent or rule" value={qInput} onChange={(e) => setQInput(e.target.value)} aria-label="Search events" />
          </div>
          <select className="select" value={filters.agentId} onChange={(e) => set('agentId', e.target.value)} aria-label="Agent">
            <option value="">All agents</option>
            {agentOptions.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            {filters.agentId && !agents.some((a) => a.id === filters.agentId) && <option value={filters.agentId}>{filters.agentId}</option>}
          </select>
          <select className="select" value={filters.action} onChange={(e) => set('action', e.target.value)} aria-label="Action">
            <option value="">All actions</option>
            {KNOWN_ACTIONS.map((a) => <option key={a} value={a}>{actionLabel(a)}</option>)}
          </select>
          <select className="select" value={filters.verdict} onChange={(e) => set('verdict', e.target.value)} aria-label="Verdict">
            <option value="">All verdicts</option>
            {VERDICTS.map((v) => <option key={v} value={v}>{v[0].toUpperCase() + v.slice(1)}</option>)}
          </select>
          <select className="select" value={filters.severity} onChange={(e) => set('severity', e.target.value)} aria-label="Severity">
            <option value="">All severities</option>
            {SEVERITIES.map((v) => <option key={v} value={v}>{v[0].toUpperCase() + v.slice(1)}</option>)}
          </select>
          <select className="select" value={filters.source} onChange={(e) => set('source', e.target.value)} aria-label="Source">
            <option value="">All sources</option>
            {EVENT_SOURCES.map((v) => <option key={v} value={v}>{SOURCE_LABELS[v]}</option>)}
          </select>
          <select className="select" value={filters.range} onChange={(e) => set('range', e.target.value)} aria-label="Time range">
            {RANGES.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
          </select>
          {activeCount > 0 && (
            <button className="btn ghost sm" onClick={() => { setFilters((f) => ({ ...fromParams(new URLSearchParams()), range: f.range })); setQInput(''); }}>
              <X size={13} />Clear {activeCount} {activeCount === 1 ? 'filter' : 'filters'}
            </button>
          )}
        </div>

        {error && <div className="panel-body"><ErrorBanner error={error} onRetry={() => setFilters((f) => ({ ...f }))} /></div>}
        {loading && <SkeletonRows rows={12} cols={5} />}
        {!loading && !error && items.length === 0 && (
          <Empty icon={Activity} title={activeCount ? 'No events match these filters' : 'No activity in this time range'}>
            {activeCount ? 'Clear a filter or widen the time range.' : 'New agent actions appear here as they happen.'}
          </Empty>
        )}
        {!loading && items.length > 0 && (
          <div className="event-list" role="table" aria-label="Events">
            <div className="event-row head" role="row">
              <span role="columnheader">Time</span><span role="columnheader">Verdict</span><span role="columnheader">Agent</span>
              <span role="columnheader">Action and target</span><span role="columnheader">Severity</span>
            </div>
            {items.map((e) => (
              <div key={e.id} role="row" tabIndex={0} className={`event-row v-${e.verdict} ${fresh.has(e.id) ? 'fresh' : ''} ${selected?.id === e.id ? 'selected' : ''}`}
                onClick={() => setSelected(e)} onKeyDown={(k) => { if (k.key === 'Enter' || k.key === ' ') { k.preventDefault(); setSelected(e); } }}>
                <span role="cell" className="num-cell ev-time">{stamp(e.ts)}</span>
                <span role="cell"><VerdictBadge verdict={e.verdict} /></span>
                <span role="cell" className="truncate ev-agent">{e.agentName}</span>
                <span role="cell" className="ev-main">
                  <span className="ev-action">{actionLabel(e.action)}{e.ruleId && <code className="ev-rule">{e.ruleId}</code>}{!e.enforced && (e.verdict === 'block' || e.verdict === 'ask') && <span className="chip warn ev-flag">Not enforced</span>}</span>
                  <span className="ev-target" title={e.target}>{e.target}</span>
                </span>
                <span role="cell"><SeverityBadge severity={e.severity} /></span>
              </div>
            ))}
            <div ref={sentinel} className="list-end">
              {loadingMore ? 'Loading older events…' : nextBefore === null ? `${num(items.length)} events · end of results` : items.length >= MAX_ROWS ? 'Showing the newest 3,000 events. Narrow the filters to see older ones.' : ''}
            </div>
          </div>
        )}
      </section>
      {selected && <EventDrawer event={selected} onClose={() => setSelected(null)} />}
      {exporting && <ExportDialog filters={filters} agents={agents} onClose={() => setExporting(false)} />}
    </div>
  );
}
