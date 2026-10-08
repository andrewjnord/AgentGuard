// In-browser implementation of the full API for VITE_MOCK builds. Imported only via a dynamic
// import guarded by import.meta.env.VITE_MOCK, so production builds tree-shake it away.
import { PolicyRejectedError, type AgentGuardApi } from '../client';
import type {
  ActivityStats, Agent, AgentEvent, Alert, AlertStatus, Approval, ApprovalDecision, ConnectionState, EventPage,
  EventQuery, ExportQuery, ExportTarget, IntegrityResult, KillSwitchAction, McpServer, Mode, PolicyHistoryEntry,
  PolicyInfo, PolicyValidation, Settings, Status, StreamMessage, TestExportResult, Trust,
} from '../types';
import { MASKED_TOKEN } from '../types';
import {
  countRules, makeEvent, pick, pickTemplate, rng, seedAgents, seedAlerts, seedApprovalHistory, seedEvents, seedMcp,
  seedPolicies, seedSettings, TEMPLATES,
} from './seed';

const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const delay = (ms = 120 + Math.random() * 180) => new Promise((r) => setTimeout(r, ms));

function notFound(what: string): never { throw new Error(`${what} not found`); }

export class MockApi implements AgentGuardApi {
  readonly isMock = true;
  private now = Date.now();
  private r = rng(4242);
  private startedAt = this.now - 19 * 3600000;
  private mode: Mode = 'enforce';
  private agentsList: Agent[];
  private mcp: McpServer[];
  private eventsList: AgentEvent[];
  private alertsList: Alert[];
  private approvalsList: Approval[];
  private policies: PolicyInfo[];
  private settingsObj: Settings;
  private splunkToken = 'b7a3e2f0-1c9d-4e55-9a51-3f0f8d6c2a11';
  private kill = { engaged: false, since: null as string | null, suspendedPids: 0 };
  private integrity: { lastVerifiedAt: string | null; ok: boolean | null };
  private listeners = new Set<(m: StreamMessage) => void>();
  private nextEventId: number;
  private nextAlertId: number;

  constructor() {
    this.agentsList = seedAgents(this.now);
    this.mcp = seedMcp(this.now);
    this.eventsList = seedEvents(this.now);
    this.alertsList = seedAlerts(this.eventsList);
    this.approvalsList = seedApprovalHistory(this.eventsList);
    this.policies = seedPolicies(this.now);
    this.settingsObj = seedSettings();
    this.integrity = { lastVerifiedAt: new Date(this.now - 2.4 * 3600000).toISOString(), ok: true };
    this.nextEventId = (this.eventsList.at(-1)?.id ?? 0) + 1;
    this.nextAlertId = Math.max(0, ...this.alertsList.map((a) => a.id)) + 1;
    this.recountAgents();
    // Two pending approvals waiting at load.
    // Oldest request first so ids stay in time order.
    this.createPending(TEMPLATES.find((t) => t.ruleId === 'mcp.postgres-writes')!, 40);
    this.createPending(TEMPLATES.find((t) => t.ruleId === 'shell.recursive-delete')!, 95);
  }

  // ---------- internals ----------
  private emit(m: StreamMessage) { for (const l of this.listeners) l(clone(m)); }

  private recountAgents() {
    const since = Date.now() - 24 * 3600000;
    for (const a of this.agentsList) { a.eventCount24h = 0; a.blockedCount24h = 0; }
    for (const e of this.eventsList) {
      if (Date.parse(e.ts) < since) continue;
      const a = this.agentsList.find((x) => x.id === e.agentId);
      if (!a) continue;
      a.eventCount24h++;
      if (e.verdict === 'block') a.blockedCount24h++;
    }
  }

  private buildStatus(): Status {
    const startOfDay = new Date(); startOfDay.setHours(0, 0, 0, 0);
    const today = this.eventsList.filter((e) => Date.parse(e.ts) >= startOfDay.getTime());
    return {
      version: '0.9.2-mock', mode: this.mode, platform: 'windows', devMode: true,
      startedAt: new Date(this.startedAt).toISOString(), uptimeSeconds: Math.floor((Date.now() - this.startedAt) / 1000),
      counts: {
        agents: this.agentsList.length, activeAgents: this.agentsList.filter((a) => a.running).length,
        mcpServers: this.mcp.length, proxiedMcpServers: this.mcp.filter((m) => m.proxied).length,
        eventsToday: today.length, blockedToday: today.filter((e) => e.verdict === 'block').length,
        askedToday: today.filter((e) => e.verdict === 'ask').length,
        openAlerts: this.alertsList.filter((a) => a.status === 'open').length,
        pendingApprovals: this.approvalsList.filter((a) => a.status === 'pending').length,
      },
      killSwitch: { ...this.kill }, integrity: { ...this.integrity },
      capabilities: { etw: true, firewall: true, processControl: true, hooks: true, mcpProxy: true },
    };
  }

  private pushEvent(e: AgentEvent) {
    this.eventsList.push(e);
    const a = this.agentsList.find((x) => x.id === e.agentId);
    if (a) {
      a.eventCount24h++; if (e.verdict === 'block') a.blockedCount24h++;
      a.lastSeen = e.ts;
    }
    this.emit({ type: 'event', data: e });
    if (e.verdict === 'block' || e.severity === 'critical') {
      const alert: Alert = {
        id: this.nextAlertId++, eventId: e.id, ts: e.ts, severity: e.severity === 'info' ? 'medium' : e.severity, status: 'open',
        title: `${e.agentName}: ${e.ruleId ?? e.action} ${e.verdict === 'block' ? 'blocked' : 'matched'}`,
        agentId: e.agentId, agentName: e.agentName, action: e.action, target: e.target, ruleId: e.ruleId,
      };
      this.alertsList.unshift(alert);
      this.emit({ type: 'alert', data: alert });
    }
  }

  private createPending(t: (typeof TEMPLATES)[number], secondsLeft: number) {
    const timeout = this.settingsObj.approvalTimeoutSeconds;
    const reqMs = Date.now() - (timeout - secondsLeft) * 1000;
    const e = makeEvent(this.r, this.nextEventId++, reqMs, t, this.mode !== 'monitor');
    this.eventsList.push(e);
    this.eventsList.sort((a, b) => a.id - b.id);
    const ap: Approval = {
      id: `apr_${Math.floor(this.r() * 1e9).toString(36)}`, eventId: e.id, requestedAt: e.ts,
      expiresAt: new Date(reqMs + timeout * 1000).toISOString(), agentId: e.agentId, agentName: e.agentName,
      action: e.action, target: e.target, details: e.details, ruleId: e.ruleId, status: 'pending', decision: null, decidedAt: null, decidedBy: null,
    };
    this.approvalsList.unshift(ap);
    return { e, ap };
  }

  private tick = () => {
    if (this.listeners.size === 0) return;
    // Expire stale approvals.
    for (const ap of this.approvalsList) {
      if (ap.status === 'pending' && Date.parse(ap.expiresAt) <= Date.now()) {
        Object.assign(ap, { status: 'expired', decision: 'timeout', decidedAt: new Date().toISOString(), decidedBy: null });
        this.emit({ type: 'approval', data: ap });
      }
    }
    if (this.kill.engaged) return; // agents are suspended: quiet stream
    const roll = this.r();
    if (roll < 0.035) {
      const asks = TEMPLATES.filter((t) => t.verdict === 'ask');
      const { e, ap } = this.createPending(pick(this.r, asks), this.settingsObj.approvalTimeoutSeconds);
      this.emit({ type: 'event', data: e });
      this.emit({ type: 'approval', data: ap });
      this.emit({ type: 'status', data: this.buildStatus() });
      return;
    }
    const t = pickTemplate(this.r);
    if (t.verdict === 'ask') return;
    const agent = this.agentsList.find((a) => a.id === t.agentId);
    if (agent && !agent.running && t.agentId !== 'mcp:postgres') return;
    const e = makeEvent(this.r, this.nextEventId++, Date.now(), t, this.mode !== 'monitor');
    if (this.mode === 'monitor' && e.verdict === 'block') e.enforced = false;
    this.pushEvent(e);
  };

  private statusTick = () => { if (this.listeners.size) this.emit({ type: 'status', data: this.buildStatus() }); };

  private agentOr404(id: string) { return this.agentsList.find((a) => a.id === id) ?? notFound('Agent'); }

  private systemEvent(action: string, target: string, details: Record<string, unknown>, agentId = 'system', agentName = 'AgentGuard') {
    const e: AgentEvent = {
      id: this.nextEventId++, ts: new Date().toISOString(), agentId, agentName, pid: null, action, target, details,
      verdict: 'log', ruleId: null, severity: 'info', source: 'system', enforced: false, hash: Math.floor(this.r() * 1e16).toString(16).padStart(64, '0'),
    };
    this.pushEvent(e);
  }

  // ---------- API ----------
  async health() { await delay(40); return { ok: true, version: '0.9.2-mock' }; }
  async status() { await delay(); return this.buildStatus(); }
  async setMode(mode: Mode) {
    await delay(); this.mode = mode;
    this.systemEvent('policy.changed', `mode → ${mode}`, { mode });
    const s = this.buildStatus(); this.emit({ type: 'status', data: s }); return s;
  }

  async activity(hours = 24): Promise<ActivityStats> {
    await delay();
    const hourMs = 3600000;
    const end = Math.floor(Date.now() / hourMs) * hourMs + hourMs;
    const start = end - hours * hourMs;
    const buckets = Array.from({ length: hours }, (_, i) => ({ ts: new Date(start + i * hourMs).toISOString(), total: 0, blocked: 0, asked: 0 }));
    const top = new Map<string, { agentId: string; agentName: string; total: number; blocked: number }>();
    for (const e of this.eventsList) {
      const t = Date.parse(e.ts); if (t < start) continue;
      const b = buckets[Math.min(hours - 1, Math.floor((t - start) / hourMs))];
      b.total++; if (e.verdict === 'block') b.blocked++; if (e.verdict === 'ask') b.asked++;
      if (e.agentId === 'system') continue;
      const ta = top.get(e.agentId) ?? { agentId: e.agentId, agentName: e.agentName, total: 0, blocked: 0 };
      ta.total++; if (e.verdict === 'block') ta.blocked++; top.set(e.agentId, ta);
    }
    return { buckets, topAgents: [...top.values()].sort((a, b) => b.total - a.total).slice(0, 6) };
  }

  async agents() { await delay(); return clone(this.agentsList); }
  async agent(id: string) { await delay(); return clone(this.agentOr404(id)); }
  async setTrust(id: string, trust: Trust) {
    await delay(); const a = this.agentOr404(id); a.trust = trust;
    this.emit({ type: 'agent', data: a }); return clone(a);
  }
  async setNetwork(id: string, blocked: boolean) {
    await delay(); const a = this.agentOr404(id); a.networkBlocked = blocked;
    this.systemEvent('system', `${blocked ? 'Blocked' : 'Unblocked'} network for ${a.name}`, { firewallRule: `AgentGuard-${a.id}-out`, blocked }, a.id, a.name);
    this.emit({ type: 'agent', data: a }); return clone(a);
  }
  async suspend(id: string) { await delay(); const a = this.agentOr404(id); this.systemEvent('system', `Suspended ${a.name}`, { pids: a.pids }, a.id, a.name); return { affected: a.pids.length }; }
  async resume(id: string) { await delay(); const a = this.agentOr404(id); this.systemEvent('system', `Resumed ${a.name}`, { pids: a.pids }, a.id, a.name); return { affected: a.pids.length }; }
  async terminate(id: string) {
    await delay(); const a = this.agentOr404(id); const n = a.pids.length;
    a.running = false; a.pids = [];
    this.systemEvent('agent.exited', `Terminated ${a.name}`, { affected: n, by: 'dashboard' }, a.id, a.name);
    this.emit({ type: 'agent', data: a }); return { affected: n };
  }
  async killSwitch(action: KillSwitchAction) {
    await delay(300);
    const running = this.agentsList.filter((a) => a.running);
    if (action === 'engage') {
      this.kill = { engaged: true, since: new Date().toISOString(), suspendedPids: running.reduce((s, a) => s + a.pids.length, 0) };
    } else if (action === 'release') {
      this.kill = { engaged: false, since: null, suspendedPids: 0 };
    } else {
      for (const a of running) { a.running = false; a.pids = []; this.emit({ type: 'agent', data: a }); }
      this.kill = { engaged: true, since: this.kill.since ?? new Date().toISOString(), suspendedPids: 0 };
    }
    this.systemEvent('killswitch', action, { action, by: 'dashboard' });
    const s = this.buildStatus(); this.emit({ type: 'status', data: s }); return s;
  }

  async mcpServers() { await delay(); return clone(this.mcp); }
  async setMcpProxy(id: string, enabled: boolean) {
    await delay(250); const m = this.mcp.find((x) => x.id === id) ?? notFound('MCP server');
    m.proxied = enabled; return clone(m);
  }
  async rescanMcp() { await delay(900); return clone(this.mcp); }

  async events(q: EventQuery): Promise<EventPage> {
    await delay();
    const limit = q.limit ?? 100;
    const text = q.q?.toLowerCase();
    const from = q.from ? Date.parse(q.from) : null;
    const to = q.to ? Date.parse(q.to) : null;
    const items: AgentEvent[] = [];
    for (let i = this.eventsList.length - 1; i >= 0 && items.length <= limit; i--) {
      const e = this.eventsList[i];
      if (q.before !== undefined && e.id >= q.before) continue;
      if (q.agentId && e.agentId !== q.agentId) continue;
      if (q.action && e.action !== q.action) continue;
      if (q.verdict && e.verdict !== q.verdict) continue;
      if (q.severity && e.severity !== q.severity) continue;
      if (q.source && e.source !== q.source) continue;
      const t = Date.parse(e.ts);
      if (from !== null && t < from) continue;
      if (to !== null && t > to) continue;
      if (text && !`${e.target} ${e.agentName} ${e.action} ${e.ruleId ?? ''} ${JSON.stringify(e.details)}`.toLowerCase().includes(text)) continue;
      items.push(e);
    }
    const more = items.length > limit;
    const page = items.slice(0, limit);
    return { items: clone(page), nextBefore: more ? page[page.length - 1].id : null };
  }
  async event(id: number) { await delay(); return clone(this.eventsList.find((e) => e.id === id) ?? notFound('Event')); }

  async alerts(status?: AlertStatus) { await delay(); return clone(status ? this.alertsList.filter((a) => a.status === status) : this.alertsList); }
  async setAlertStatus(id: number, status: AlertStatus) {
    await delay(); const a = this.alertsList.find((x) => x.id === id) ?? notFound('Alert');
    a.status = status; this.emit({ type: 'alert', data: a }); return clone(a);
  }

  async approvals(status?: Approval['status']) { await delay(); return clone(status ? this.approvalsList.filter((a) => a.status === status) : this.approvalsList); }
  async decide(id: string, decision: ApprovalDecision) {
    await delay(); const a = this.approvalsList.find((x) => x.id === id) ?? notFound('Approval');
    if (a.status !== 'pending') throw new Error('This approval has already been decided.');
    Object.assign(a, { status: decision === 'deny' ? 'denied' : 'allowed', decision, decidedAt: new Date().toISOString(), decidedBy: 'dashboard' });
    this.emit({ type: 'approval', data: a });
    this.systemEvent('approval.decided', `${a.action} ${a.target}`, { approvalId: a.id, decision }, a.agentId, a.agentName);
    this.emit({ type: 'status', data: this.buildStatus() });
    return clone(a);
  }

  private validate(yaml: string): PolicyValidation {
    const errors: PolicyValidation['errors'] = [];
    const lines = yaml.split('\n');
    const ids = new Map<string, number>();
    lines.forEach((ln, i) => {
      if (/\t/.test(ln)) errors.push({ line: i + 1, column: ln.indexOf('\t') + 1, message: 'Tabs are not allowed for indentation; use spaces.' });
      const v = ln.match(/^\s*verdict:\s*(\S+)/);
      if (v && !['allow', 'log', 'ask', 'block'].includes(v[1])) errors.push({ line: i + 1, column: ln.indexOf(v[1]) + 1, message: `Unknown verdict "${v[1]}". Expected allow, log, ask or block.` });
      const m = ln.match(/^\s*mode:\s*(\S+)/);
      if (m && !['monitor', 'enforce', 'strict'].includes(m[1])) errors.push({ line: i + 1, column: ln.indexOf(m[1]) + 1, message: `Unknown mode "${m[1]}".` });
      const id = ln.match(/^\s*- id:\s*(\S+)/);
      if (id) {
        if (ids.has(id[1])) errors.push({ line: i + 1, column: ln.indexOf(id[1]) + 1, message: `Duplicate rule id "${id[1]}" (first defined on line ${ids.get(id[1])}).` });
        else ids.set(id[1], i + 1);
      }
      const q = (ln.match(/"/g) ?? []).length;
      if (q % 2 === 1) errors.push({ line: i + 1, column: ln.indexOf('"') + 1, message: 'Unterminated quoted string.' });
    });
    if (!/^rules:/m.test(yaml)) errors.push({ line: null, column: null, message: 'Missing top-level "rules" list.' });
    return { ok: errors.length === 0, ruleCount: countRules(yaml), errors };
  }

  async policy() { await delay(); return clone({ ...this.policies[this.policies.length - 1], mode: this.mode }); }
  async validatePolicy(yaml: string) { await delay(200); return this.validate(yaml); }
  async applyPolicy(yaml: string) {
    await delay(300);
    const v = this.validate(yaml);
    if (!v.ok) throw new PolicyRejectedError(v);
    const m = yaml.match(/^mode:\s*(monitor|enforce|strict)/m);
    if (m) this.mode = m[1] as Mode;
    const info: PolicyInfo = { yaml, version: this.policies.length + 1, appliedAt: new Date().toISOString(), appliedBy: 'dashboard', ruleCount: v.ruleCount, mode: this.mode };
    this.policies.push(info);
    this.systemEvent('policy.changed', `Policy v${info.version} applied`, { version: info.version, ruleCount: info.ruleCount });
    this.emit({ type: 'status', data: this.buildStatus() });
    return clone(info);
  }
  async policyHistory(): Promise<PolicyHistoryEntry[]> {
    await delay();
    return this.policies.map(({ version, appliedAt, appliedBy, ruleCount }) => ({ version, appliedAt, appliedBy, ruleCount })).reverse();
  }
  async policyVersion(version: number) { await delay(); return clone(this.policies.find((p) => p.version === version) ?? notFound('Policy version')); }

  async settings() { await delay(); return clone(this.settingsObj); }
  async saveSettings(s: Settings) {
    await delay(300);
    const next = clone(s);
    if (next.exports.splunk.token !== MASKED_TOKEN) this.splunkToken = next.exports.splunk.token ?? '';
    next.exports.splunk.token = this.splunkToken ? MASKED_TOKEN : null;
    this.settingsObj = next;
    return clone(next);
  }
  async testExport(target: ExportTarget): Promise<TestExportResult> {
    await delay(700);
    const e = this.settingsObj.exports;
    if (target === 'splunk') return e.splunk.url ? { ok: true, message: `HEC accepted test event (index=${e.splunk.index}, 38 ms).` } : { ok: false, message: 'Splunk HEC URL is empty.' };
    if (target === 'syslog') return { ok: false, message: `Could not connect to ${e.syslog.host}:${e.syslog.port}/${e.syslog.protocol} (connection refused).` };
    return { ok: true, message: `Wrote test record to ${e.jsonFile.directory}\\agentguard-test.ndjson.` };
  }

  async verifyIntegrity(): Promise<IntegrityResult> {
    await delay(1100);
    const verifiedAt = new Date().toISOString();
    this.integrity = { lastVerifiedAt: verifiedAt, ok: true };
    this.emit({ type: 'status', data: this.buildStatus() });
    return { ok: true, checked: this.eventsList.length, firstBadId: null, verifiedAt };
  }

  async download(q: ExportQuery) {
    await delay();
    const items = this.eventsList.filter((e) => (!q.agentId || e.agentId === q.agentId)
      && (!q.from || Date.parse(e.ts) >= Date.parse(q.from)) && (!q.to || Date.parse(e.ts) <= Date.parse(q.to)));
    let body: string; let type = 'application/x-ndjson'; let ext = 'ndjson';
    if (q.format === 'cef') {
      type = 'text/plain'; ext = 'cef';
      body = items.map((e) => `CEF:0|AgentGuard|AgentGuard for Windows|0.9.2|${e.ruleId ?? e.action}|${e.action}|${({ info: 1, low: 3, medium: 5, high: 8, critical: 10 })[e.severity]}|rt=${Date.parse(e.ts)} suser=${e.agentName} act=${e.verdict} request=${e.target.replace(/[=|\\]/g, (c) => `\\${c}`)}`).join('\n');
    } else if (q.format === 'ocsf') {
      body = items.map((e) => JSON.stringify({ class_uid: 1007, category_uid: 1, time: Date.parse(e.ts), severity: e.severity, activity_name: e.action, actor: { app_name: e.agentName, process: { pid: e.pid } }, disposition: e.verdict, unmapped: { target: e.target, rule_id: e.ruleId, hash: e.hash } })).join('\n');
    } else {
      body = items.map((e) => JSON.stringify(e)).join('\n');
    }
    const url = URL.createObjectURL(new Blob([body], { type }));
    const a = document.createElement('a'); a.href = url; a.download = `agentguard-events.${q.format}.${ext}`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  private timers: number[] = [];
  subscribe(onMessage: (m: StreamMessage) => void, onState: (s: ConnectionState) => void) {
    onState('connecting');
    this.listeners.add(onMessage);
    const hello = window.setTimeout(() => { onState('open'); onMessage({ type: 'hello', data: this.buildStatus() }); }, 250);
    if (this.timers.length === 0) {
      const schedule = () => {
        this.timers[0] = window.setTimeout(() => { this.tick(); schedule(); }, 900 + Math.random() * 2600);
      };
      schedule();
      this.timers[1] = window.setInterval(this.statusTick, 10000);
    }
    return () => {
      window.clearTimeout(hello);
      this.listeners.delete(onMessage);
      if (this.listeners.size === 0) { window.clearTimeout(this.timers[0]); window.clearInterval(this.timers[1]); this.timers = []; }
    };
  }
}
