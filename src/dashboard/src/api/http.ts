import { getToken } from './auth';
import { ApiError, PolicyRejectedError, UnauthorizedError, isPolicyValidation, type AgentGuardApi } from './client';
import type {
  ActivityStats, Agent, AgentEvent, Alert, AlertStatus, Approval, ApprovalDecision, ConnectionState, EventPage,
  EventQuery, ExportQuery, ExportTarget, IntegrityResult, KillSwitchAction, McpServer, Mode, PolicyHistoryEntry,
  PolicyInfo, PolicyValidation, Settings, Status, StreamMessage, StreamType, TestExportResult, Trust,
} from './types';
import { STREAM_TYPES } from './types';

const BASE = '/api/v1';

type Query = Record<string, string | number | undefined | null>;

function qs(params: Query): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

const enc = encodeURIComponent;

export class HttpApi implements AgentGuardApi {
  readonly isMock = false;
  private readonly onUnauthorized: () => void;

  constructor(onUnauthorized: () => void) {
    this.onUnauthorized = onUnauthorized;
  }

  private async request<T>(method: string, path: string, body?: unknown, opts: { auth?: boolean; allow400?: boolean } = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const auth = opts.auth ?? true;
    if (auth) {
      const token = getToken();
      if (!token) { this.onUnauthorized(); throw new UnauthorizedError(); }
      headers['X-AgentGuard-Token'] = token;
    }
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    let res: Response;
    try {
      res = await fetch(BASE + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: 'same-origin',
        cache: 'no-store',
      });
    } catch {
      throw new ApiError(0, 'The AgentGuard service is not reachable. Check that the service is running.');
    }

    if (res.status === 401) { this.onUnauthorized(); throw new UnauthorizedError(); }

    const text = await res.text();
    let data: unknown = undefined;
    if (text) { try { data = JSON.parse(text); } catch { data = text; } }

    if (res.status === 400 && opts.allow400 && isPolicyValidation(data)) throw new PolicyRejectedError(data);
    if (!res.ok) {
      const msg = (data && typeof data === 'object' && ('message' in data || 'error' in data))
        ? String((data as { message?: unknown; error?: unknown }).message ?? (data as { error?: unknown }).error)
        : `Request failed (${res.status} ${res.statusText})`;
      throw new ApiError(res.status, msg, data);
    }
    return data as T;
  }

  health() { return this.request<{ ok: boolean; version: string }>('GET', '/health', undefined, { auth: false }); }
  status() { return this.request<Status>('GET', '/status'); }
  setMode(mode: Mode) { return this.request<Status>('PUT', '/mode', { mode }); }
  activity(hours = 24) { return this.request<ActivityStats>('GET', `/stats/activity${qs({ hours })}`); }

  agents() { return this.request<Agent[]>('GET', '/agents'); }
  agent(id: string) { return this.request<Agent>('GET', `/agents/${enc(id)}`); }
  setTrust(id: string, trust: Trust) { return this.request<Agent>('PUT', `/agents/${enc(id)}/trust`, { trust }); }
  setNetwork(id: string, blocked: boolean) { return this.request<Agent>('PUT', `/agents/${enc(id)}/network`, { blocked }); }
  suspend(id: string) { return this.request<{ affected: number }>('POST', `/agents/${enc(id)}/suspend`); }
  resume(id: string) { return this.request<{ affected: number }>('POST', `/agents/${enc(id)}/resume`); }
  terminate(id: string) { return this.request<{ affected: number }>('POST', `/agents/${enc(id)}/terminate`); }
  killSwitch(action: KillSwitchAction) { return this.request<Status>('POST', '/killswitch', { action }); }

  mcpServers() { return this.request<McpServer[]>('GET', '/mcp'); }
  setMcpProxy(id: string, enabled: boolean) { return this.request<McpServer>('PUT', `/mcp/${enc(id)}/proxy`, { enabled }); }
  rescanMcp() { return this.request<McpServer[]>('POST', '/mcp/rescan'); }

  events(q: EventQuery) {
    return this.request<EventPage>('GET', `/events${qs({
      agentId: q.agentId, action: q.action, verdict: q.verdict, severity: q.severity, source: q.source,
      q: q.q, from: q.from, to: q.to, before: q.before, limit: q.limit ?? 100,
    })}`);
  }
  event(id: number) { return this.request<AgentEvent>('GET', `/events/${id}`); }

  alerts(status?: AlertStatus) { return this.request<Alert[]>('GET', `/alerts${qs({ status })}`); }
  setAlertStatus(id: number, status: AlertStatus) { return this.request<Alert>('PUT', `/alerts/${id}`, { status }); }

  approvals(status?: Approval['status']) { return this.request<Approval[]>('GET', `/approvals${qs({ status })}`); }
  decide(id: string, decision: ApprovalDecision) { return this.request<Approval>('POST', `/approvals/${enc(id)}`, { decision }); }

  policy() { return this.request<PolicyInfo>('GET', '/policy'); }
  validatePolicy(yaml: string) { return this.request<PolicyValidation>('POST', '/policy/validate', { yaml }); }
  applyPolicy(yaml: string) { return this.request<PolicyInfo>('PUT', '/policy', { yaml }, { allow400: true }); }
  policyHistory() { return this.request<PolicyHistoryEntry[]>('GET', '/policy/history'); }
  policyVersion(version: number) { return this.request<PolicyInfo>('GET', `/policy/history/${version}`); }

  settings() { return this.request<Settings>('GET', '/settings'); }
  saveSettings(s: Settings) { return this.request<Settings>('PUT', '/settings', s); }
  testExport(target: ExportTarget) { return this.request<TestExportResult>('POST', '/settings/test-export', { target }); }

  verifyIntegrity() { return this.request<IntegrityResult>('POST', '/integrity/verify'); }

  async download(q: ExportQuery): Promise<void> {
    const token = getToken();
    if (!token) { this.onUnauthorized(); throw new UnauthorizedError(); }
    const url = `${BASE}/export${qs({ format: q.format, from: q.from, to: q.to, agentId: q.agentId, token })}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = '';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  subscribe(onMessage: (m: StreamMessage) => void, onState: (s: ConnectionState) => void): () => void {
    let es: EventSource | null = null;
    let timer: number | undefined;
    let attempt = 0;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      const token = getToken();
      if (!token) { onState('offline'); this.onUnauthorized(); return; }
      onState(attempt === 0 ? 'connecting' : 'reconnecting');
      es = new EventSource(`${BASE}/stream${qs({ token })}`);
      es.onopen = () => { attempt = 0; onState('open'); };
      for (const type of STREAM_TYPES) {
        es.addEventListener(type, (ev: MessageEvent<string>) => {
          try {
            const data: unknown = JSON.parse(ev.data);
            onMessage({ type: type as StreamType, data } as StreamMessage);
          } catch { /* malformed message: ignore */ }
        });
      }
      es.onerror = () => {
        // Take over reconnection from the browser so we control backoff and can detect a revoked token.
        es?.close();
        es = null;
        if (disposed) return;
        attempt += 1;
        onState(attempt > 3 ? 'offline' : 'reconnecting');
        const delay = Math.min(15000, 500 * 2 ** Math.min(attempt, 5)) + Math.random() * 400;
        // A 401 on the stream is indistinguishable from a network error; probe a JSON endpoint.
        if (attempt === 2 || attempt % 5 === 0) this.status().catch(() => undefined);
        timer = window.setTimeout(connect, delay);
      };
    };

    connect();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
      es?.close();
    };
  }
}
