import { useMemo, useState } from 'react';
import { Activity, Bot, CirclePause, CirclePlay, Globe, Search, ShieldOff, Skull } from 'lucide-react';
import type { Agent, Enforcement, Trust } from '../api/types';
import { Dialog, Drawer, Empty, ErrorBanner, KIND_LABELS, KindIcon, SkeletonRows } from '../components/ui';
import { ago, errMsg, fullDate, num } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { href, navigate, useRoute } from '../lib/router';
import { useApp, useStream } from '../lib/store';

const COVERAGE: { key: keyof Enforcement; label: string; help: string }[] = [
  { key: 'hooks', label: 'Hooks', help: 'Actions are checked before they run' },
  { key: 'mcpProxy', label: 'MCP proxy', help: 'MCP tool calls pass through AgentGuard' },
  { key: 'firewall', label: 'Firewall', help: 'Outbound network can be blocked' },
  { key: 'processControl', label: 'Process control', help: 'Can be suspended or terminated' },
];

export function CoverageChips({ e }: { e: Enforcement }) {
  return (
    <span className="chips">
      {COVERAGE.map((c) => (
        <span key={c.key} className={`chip ${e[c.key] ? 'on' : 'off'}`} title={`${c.label}: ${e[c.key] ? c.help : 'not available for this agent'}`}>
          {c.label}
        </span>
      ))}
      {e.fileDetectOnly && <span className="chip warn" title="File access is observed through ETW and cannot be prevented, only detected">Files: detect-only</span>}
    </span>
  );
}

function TrustBadge({ trust }: { trust: Trust }) {
  const label = { allowed: 'Trusted', blocked: 'Blocked', unknown: 'Unreviewed' }[trust];
  return <span className={`trust ${trust}`}>{label}</span>;
}

function RunState({ a }: { a: Agent }) {
  return (
    <span className={`run ${a.running ? 'on' : ''}`}>
      <i aria-hidden="true" />{a.running ? 'Running' : `Last seen ${ago(a.lastSeen)}`}
    </span>
  );
}

type Confirm = { kind: 'terminate' | 'suspend' | 'network'; agent: Agent } | null;

function AgentDrawer({ agent, onClose, onChange }: { agent: Agent; onClose: () => void; onChange: (a: Agent) => void }) {
  const { api, toast } = useApp();
  const [busy, setBusy] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm>(null);

  const act = async (key: string, fn: () => Promise<void>) => {
    setBusy(key); setConfirm(null);
    try { await fn(); } catch (e) { toast(errMsg(e), 'error'); } finally { setBusy(null); }
  };
  const setTrust = (t: Trust) => act(`trust-${t}`, async () => { onChange(await api.setTrust(agent.id, t)); toast(`${agent.name} marked ${t === 'allowed' ? 'trusted' : t === 'blocked' ? 'blocked' : 'unreviewed'}`, 'ok'); });
  const setNet = (blocked: boolean) => act('net', async () => { onChange(await api.setNetwork(agent.id, blocked)); toast(blocked ? `Network blocked for ${agent.name}` : `Network restored for ${agent.name}`, 'ok'); });
  const proc = (kind: 'suspend' | 'resume' | 'terminate') => act(kind, async () => {
    const r = kind === 'suspend' ? await api.suspend(agent.id) : kind === 'resume' ? await api.resume(agent.id) : await api.terminate(agent.id);
    toast(`${kind === 'suspend' ? 'Suspended' : kind === 'resume' ? 'Resumed' : 'Terminated'} ${num(r.affected)} ${r.affected === 1 ? 'process' : 'processes'}`, 'ok');
    if (kind === 'terminate') onChange({ ...agent, running: false, pids: [] });
  });
  const noProc = !agent.enforcement.processControl || !agent.running;

  return (
    <Drawer title={agent.name} subtitle={<span className="row"><span>{KIND_LABELS[agent.kind]}</span><TrustBadge trust={agent.trust} /></span>} icon={<KindIcon kind={agent.kind} />} onClose={onClose}
      footer={<button className="btn" onClick={() => navigate('timeline', { agentId: agent.id })}><Activity size={14} />View activity in timeline</button>}>
      <div className="stat-pair">
        <div><span className="num-big">{num(agent.eventCount24h)}</span><span className="muted">actions in 24 h</span></div>
        <div><span className={`num-big ${agent.blockedCount24h ? 'block-ink' : ''}`}>{num(agent.blockedCount24h)}</span><span className="muted">blocked in 24 h</span></div>
        <div><RunState a={agent} /><span className="muted">{agent.pids.length ? `PID ${agent.pids.join(', ')}` : 'No processes'}</span></div>
      </div>

      <section>
        <div className="section-title">Trust</div>
        <div className="segmented" role="radiogroup" aria-label="Trust">
          {(['allowed', 'unknown', 'blocked'] as Trust[]).map((t) => (
            <button key={t} role="radio" aria-checked={agent.trust === t} data-t={t} disabled={!!busy} onClick={() => agent.trust !== t && setTrust(t)}>
              {{ allowed: 'Trusted', unknown: 'Unreviewed', blocked: 'Blocked' }[t]}
            </button>
          ))}
        </div>
        <p className="hint muted">Blocked agents have every action denied. Trusted agents still follow the policy rules.</p>
      </section>

      <section>
        <div className="section-title">Controls</div>
        <div className="control-list">
          <div className="control">
            <Globe size={16} />
            <div className="stack"><span className="strong">Network access</span><span className="muted">{agent.enforcement.firewall ? (agent.networkBlocked ? 'Outbound connections are blocked by Windows Firewall.' : 'Allowed, subject to policy.') : 'Firewall control is not available for this agent.'}</span></div>
            {agent.networkBlocked
              ? <button className="btn sm" disabled={!!busy || !agent.enforcement.firewall} onClick={() => setNet(false)}>Unblock</button>
              : <button className="btn sm danger-outline" disabled={!!busy || !agent.enforcement.firewall} onClick={() => setConfirm({ kind: 'network', agent })}>Block network</button>}
          </div>
          <div className="control">
            <CirclePause size={16} />
            <div className="stack"><span className="strong">Pause the agent</span><span className="muted">Suspends its process tree. Nothing is lost.</span></div>
            <div className="row">
              <button className="btn sm" disabled={!!busy || noProc} onClick={() => setConfirm({ kind: 'suspend', agent })}>Suspend</button>
              <button className="btn sm" disabled={!!busy || noProc} onClick={() => proc('resume')}><CirclePlay size={13} />Resume</button>
            </div>
          </div>
          <div className="control">
            <Skull size={16} />
            <div className="stack"><span className="strong">Terminate</span><span className="muted">Ends every process of this agent. Unsaved work is lost.</span></div>
            <button className="btn sm danger-outline" disabled={!!busy || noProc} onClick={() => setConfirm({ kind: 'terminate', agent })}>Terminate</button>
          </div>
        </div>
      </section>

      <section>
        <div className="section-title">Enforcement coverage</div>
        <CoverageChips e={agent.enforcement} />
      </section>

      <section>
        <div className="section-title">Identity</div>
        <dl className="kv">
          <dt>Agent ID</dt><dd><code>{agent.id}</code></dd>
          <dt>Executable</dt><dd className="path">{agent.exePath ?? '–'}</dd>
          <dt>Publisher</dt><dd>{agent.publisher ?? 'Unknown'}{agent.signerValid === true && <span className="chip ok" style={{ marginLeft: 6 }}>Signature valid</span>}{agent.signerValid === false && <span className="chip bad" style={{ marginLeft: 6 }}>Signature invalid</span>}</dd>
          <dt>First seen</dt><dd>{fullDate(agent.firstSeen)}</dd>
          <dt>Last seen</dt><dd>{fullDate(agent.lastSeen)}</dd>
          {agent.mcpServerIds.length > 0 && (<><dt>MCP servers</dt><dd><a href={href('mcp')}>{agent.mcpServerIds.length} configured</a></dd></>)}
        </dl>
      </section>

      {confirm && (
        <Dialog onClose={() => setConfirm(null)}
          title={confirm.kind === 'terminate' ? `Terminate ${agent.name}?` : confirm.kind === 'suspend' ? `Suspend ${agent.name}?` : `Block network for ${agent.name}?`}
          footer={<>
            <button className="btn" onClick={() => setConfirm(null)} data-autofocus>Cancel</button>
            <button className={`btn ${confirm.kind === 'terminate' ? 'danger' : 'primary'}`}
              onClick={() => (confirm.kind === 'network' ? setNet(true) : proc(confirm.kind))}>
              {confirm.kind === 'terminate' ? 'Terminate' : confirm.kind === 'suspend' ? 'Suspend' : 'Block network'}
            </button>
          </>}>
          <p className="ink2">
            {confirm.kind === 'terminate' && `${num(agent.pids.length)} processes will be ended immediately. Anything the agent has not saved will be lost.`}
            {confirm.kind === 'suspend' && `${num(agent.pids.length)} processes will be frozen until you resume them. The agent's UI will stop responding.`}
            {confirm.kind === 'network' && 'AgentGuard adds a Windows Firewall rule that blocks all outbound connections from this agent. Model API calls will fail until you unblock it.'}
          </p>
        </Dialog>
      )}
    </Drawer>
  );
}

export default function Agents() {
  const { api } = useApp();
  const route = useRoute();
  const agents = useAsync(() => api.agents(), [api]);
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<'all' | 'running' | 'review'>('all');
  const selectedId = route.params.get('id');

  useStream((m) => {
    if (m.type === 'agent') agents.setData((l) => {
      if (!l) return l;
      return l.some((a) => a.id === m.data.id) ? l.map((a) => (a.id === m.data.id ? { ...a, ...m.data } : a)) : [...l, m.data];
    });
    if (m.type === 'event') agents.setData((l) => l?.map((a) => a.id === m.data.agentId
      ? { ...a, eventCount24h: a.eventCount24h + 1, blockedCount24h: a.blockedCount24h + (m.data.verdict === 'block' ? 1 : 0), lastSeen: m.data.ts }
      : a));
  });

  const list = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (agents.data ?? [])
      .filter((a) => filter === 'all' || (filter === 'running' ? a.running : a.trust === 'unknown'))
      .filter((a) => !t || `${a.name} ${a.id} ${a.publisher ?? ''} ${a.exePath ?? ''}`.toLowerCase().includes(t))
      .sort((a, b) => Number(b.running) - Number(a.running) || b.eventCount24h - a.eventCount24h);
  }, [agents.data, q, filter]);

  const selected = agents.data?.find((a) => a.id === selectedId) ?? null;
  const counts = { all: agents.data?.length ?? 0, running: agents.data?.filter((a) => a.running).length ?? 0, review: agents.data?.filter((a) => a.trust === 'unknown').length ?? 0 };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Agents</h1>
          <p className="lede">Every AI agent AgentGuard has found on this PC, and how much of what it does can be controlled.</p>
        </div>
      </div>
      <section className="panel">
        <div className="toolbar">
          <div className="segmented small" role="radiogroup" aria-label="Show">
            {(['all', 'running', 'review'] as const).map((f) => (
              <button key={f} role="radio" aria-checked={filter === f} onClick={() => setFilter(f)}>
                {{ all: 'All', running: 'Running', review: 'Needs review' }[f]} <span className="muted num-cell">{counts[f]}</span>
              </button>
            ))}
          </div>
          <div className="input-icon" style={{ width: 260, maxWidth: '100%' }}>
            <Search size={14} /><input className="input" placeholder="Filter by name or path" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter agents" />
          </div>
        </div>
        {agents.error && <div className="panel-body"><ErrorBanner error={agents.error} onRetry={agents.reload} /></div>}
        {!agents.data && !agents.error && <SkeletonRows rows={7} cols={6} />}
        {agents.data && list.length === 0 && (
          agents.data.length === 0
            ? <Empty icon={Bot} title="No agents discovered yet">AgentGuard looks for Claude Code, Cursor, VS Code, Ollama, MCP servers and agent-like processes. Start one and it appears here within seconds.</Empty>
            : <Empty icon={ShieldOff} title="No agents match">Try a different filter.</Empty>
        )}
        {list.length > 0 && (
          <div className="table-wrap">
            <table className="data agents-table">
              <thead>
                <tr>
                  <th>Agent</th><th>State</th><th>Trust</th><th>Enforcement coverage</th><th className="num">Actions 24 h</th><th className="num">Blocked</th>
                </tr>
              </thead>
              <tbody>
                {list.map((a) => (
                  <tr key={a.id} className="clickable" aria-selected={a.id === selectedId} tabIndex={0}
                    onClick={() => navigate('agents', { id: a.id })}
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate('agents', { id: a.id }); } }}>
                    <td>
                      <span className="row" style={{ gap: 10 }}>
                        <KindIcon kind={a.kind} />
                        <span className="stack">
                          <span className="strong truncate">{a.name}{a.networkBlocked && <span className="chip bad" style={{ marginLeft: 6 }}>Network blocked</span>}</span>
                          <span className="muted truncate" style={{ fontSize: 'var(--fs-xs)' }}>{a.publisher ?? KIND_LABELS[a.kind]}</span>
                        </span>
                      </span>
                    </td>
                    <td><span className="stack"><RunState a={a} />{a.pids.length > 0 && <span className="muted mono" style={{ fontSize: 11 }}>PID {a.pids.slice(0, 3).join(', ')}{a.pids.length > 3 ? ` +${a.pids.length - 3}` : ''}</span>}</span></td>
                    <td><TrustBadge trust={a.trust} /></td>
                    <td><CoverageChips e={a.enforcement} /></td>
                    <td className="num num-cell">{num(a.eventCount24h)}</td>
                    <td className={`num num-cell ${a.blockedCount24h ? 'block-ink strong' : 'muted'}`}>{num(a.blockedCount24h)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {selected && (
        <AgentDrawer agent={selected} onClose={() => navigate('agents')}
          onChange={(a) => agents.setData((l) => l?.map((x) => (x.id === a.id ? a : x)))} />
      )}
    </div>
  );
}
