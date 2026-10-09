const nf = new Intl.NumberFormat(undefined);
export const num = (n: number | null | undefined) => (n === null || n === undefined ? '–' : nf.format(n));

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const hmFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
const dateTimeFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
const fullFmt = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

export const time = (iso: string) => timeFmt.format(new Date(iso));
export const hm = (iso: string) => hmFmt.format(new Date(iso));
export const dateTime = (iso: string | null) => (iso ? dateTimeFmt.format(new Date(iso)) : '–');
export const fullDate = (iso: string | null) => (iso ? fullFmt.format(new Date(iso)) : '–');

export function isToday(iso: string) {
  const d = new Date(iso); const n = new Date();
  return d.getFullYear() === n.getFullYear() && d.getMonth() === n.getMonth() && d.getDate() === n.getDate();
}

/** Short timestamp for dense rows: HH:MM:SS today, otherwise "Oct 7, 14:02". */
export const stamp = (iso: string) => (isToday(iso) ? time(iso) : dateTime(iso));

export function ago(iso: string | null, now = Date.now()): string {
  if (!iso) return 'never';
  const s = Math.round((now - Date.parse(iso)) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60); if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60); if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24); return `${d} d ago`;
}

export function duration(seconds: number): string {
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600), m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

export function countdown(ms: number): string {
  const s = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

export const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`;

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

const ACTION_LABELS: Record<string, string> = {
  'process.start': 'Process start', 'shell.exec': 'Shell command', 'file.read': 'File read', 'file.write': 'File write',
  'file.delete': 'File delete', 'net.connect': 'Network connect', 'mcp.call': 'MCP tool call', 'agent.discovered': 'Agent discovered',
  'agent.exited': 'Agent exited', 'approval.decided': 'Approval decided', 'policy.changed': 'Policy changed', killswitch: 'Kill switch', system: 'System',
};
export const actionLabel = (a: string) => ACTION_LABELS[a] ?? a;

export const SOURCE_LABELS: Record<string, string> = {
  hook: 'Agent hook', 'mcp-proxy': 'MCP proxy', etw: 'ETW sensor', discovery: 'Discovery', system: 'System', demo: 'Demo',
};

type Caps = { processControl: boolean; firewall: boolean };

/** What the kill switch actually does on this machine, so the UI never claims more than the service can enforce. */
export function killSwitchEffect(caps: Caps | undefined): string {
  const parts = ['every action checked by AgentGuard is blocked'];
  if (caps?.processControl) parts.push('AI agent processes are suspended');
  if (caps?.firewall) parts.push('their network access is cut');
  return parts.length === 1 ? parts[0] : parts.slice(0, -1).join(', ') + ' and ' + parts[parts.length - 1];
}

/** Sentence-case version for the start of a sentence. */
export function KillSwitchEffect(caps: Caps | undefined): string {
  const s = killSwitchEffect(caps);
  return s.charAt(0).toUpperCase() + s.slice(1);
}
