// Types mirror docs/api.md (v1) exactly. Keep in sync with the contract.

export type AgentKind = 'cli' | 'desktop' | 'ide-extension' | 'local-model' | 'mcp-server' | 'unknown';
export type Trust = 'unknown' | 'allowed' | 'blocked';
export type Verdict = 'allow' | 'log' | 'ask' | 'block';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Mode = 'monitor' | 'enforce' | 'strict';
/** Open set: known values listed, any string accepted. */
export type Action =
  | 'process.start' | 'shell.exec' | 'file.read' | 'file.write' | 'file.delete' | 'net.connect'
  | 'mcp.call' | 'agent.discovered' | 'agent.exited' | 'approval.decided' | 'policy.changed'
  | 'killswitch' | 'system';
export type EventSourceKind = 'hook' | 'mcp-proxy' | 'etw' | 'discovery' | 'system' | 'demo';

export const VERDICTS: Verdict[] = ['allow', 'log', 'ask', 'block'];
export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const MODES: Mode[] = ['monitor', 'enforce', 'strict'];
export const KNOWN_ACTIONS: Action[] = [
  'process.start', 'shell.exec', 'file.read', 'file.write', 'file.delete', 'net.connect', 'mcp.call',
  'agent.discovered', 'agent.exited', 'approval.decided', 'policy.changed', 'killswitch', 'system',
];
export const EVENT_SOURCES: EventSourceKind[] = ['hook', 'mcp-proxy', 'etw', 'discovery', 'system', 'demo'];

export interface Capabilities { etw: boolean; firewall: boolean; processControl: boolean; hooks: boolean; mcpProxy: boolean }

export interface Status {
  version: string;
  mode: Mode;
  platform: string;
  devMode: boolean;
  startedAt: string;
  uptimeSeconds: number;
  counts: {
    agents: number; activeAgents: number;
    mcpServers: number; proxiedMcpServers: number;
    eventsToday: number; blockedToday: number; askedToday: number;
    openAlerts: number; pendingApprovals: number;
  };
  killSwitch: { engaged: boolean; since: string | null; suspendedPids: number };
  integrity: { lastVerifiedAt: string | null; ok: boolean | null };
  capabilities: Capabilities;
}

export interface Enforcement { hooks: boolean; mcpProxy: boolean; firewall: boolean; processControl: boolean; fileDetectOnly: boolean }

export interface Agent {
  id: string;
  kind: AgentKind;
  name: string;
  exePath: string | null;
  publisher: string | null;
  signerValid: boolean | null;
  firstSeen: string;
  lastSeen: string;
  trust: Trust;
  running: boolean;
  pids: number[];
  networkBlocked: boolean;
  enforcement: Enforcement;
  eventCount24h: number;
  blockedCount24h: number;
  mcpServerIds: string[];
}

export interface McpServer {
  id: string;
  name: string;
  client: string;
  configPath: string;
  scope: 'user' | 'project';
  transport: 'stdio' | 'http';
  command: string | null;
  args: string[];
  url: string | null;
  proxied: boolean;
  agentId: string;
  lastCallAt: string | null;
}

export interface AgentEvent {
  id: number;
  ts: string;
  agentId: string;
  agentName: string;
  pid: number | null;
  action: string;
  target: string;
  details: Record<string, unknown>;
  verdict: Verdict;
  ruleId: string | null;
  severity: Severity;
  source: EventSourceKind;
  enforced: boolean;
  hash: string;
}

export type AlertStatus = 'open' | 'acked' | 'closed';
export interface Alert {
  id: number; eventId: number; ts: string; severity: Severity;
  status: AlertStatus;
  title: string; agentId: string; agentName: string; action: string; target: string; ruleId: string | null;
}

export type ApprovalStatus = 'pending' | 'allowed' | 'denied' | 'expired';
export type ApprovalDecision = 'allow_once' | 'allow_always' | 'deny';
export interface Approval {
  id: string; eventId: number; requestedAt: string; expiresAt: string;
  agentId: string; agentName: string; action: string; target: string;
  details: Record<string, unknown>; ruleId: string | null;
  status: ApprovalStatus;
  decision: ApprovalDecision | 'timeout' | null;
  decidedAt: string | null; decidedBy: string | null;
}

export interface PolicyInfo { yaml: string; version: number; appliedAt: string; appliedBy: string; ruleCount: number; mode: Mode }
export interface PolicyError { line: number | null; column: number | null; message: string }
export interface PolicyValidation { ok: boolean; ruleCount: number; errors: PolicyError[] }
export interface PolicyHistoryEntry { version: number; appliedAt: string; appliedBy: string; ruleCount: number }

export interface Settings {
  retentionDays: number;
  failMode: 'closed' | 'open';
  autoSuspendOnDetectBlock: boolean;
  approvalTimeoutSeconds: number;
  exports: {
    splunk: { enabled: boolean; url: string; token: string | null; index: string; sourcetype: string; verifyTls: boolean };
    syslog: { enabled: boolean; host: string; port: number; protocol: 'udp' | 'tcp' };
    jsonFile: { enabled: boolean; directory: string };
  };
  redaction: { patterns: string[] };
}
export type ExportTarget = 'splunk' | 'syslog' | 'jsonFile';
export const MASKED_TOKEN = '********';

export interface ActivityBucket { ts: string; total: number; blocked: number; asked: number }
export interface TopAgent { agentId: string; agentName: string; total: number; blocked: number }
export interface ActivityStats { buckets: ActivityBucket[]; topAgents: TopAgent[] }

export interface EventQuery {
  agentId?: string; action?: string; verdict?: string; severity?: string; source?: string;
  q?: string; from?: string; to?: string; before?: number; limit?: number;
}
export interface EventPage { items: AgentEvent[]; nextBefore: number | null }

export interface IntegrityResult { ok: boolean; checked: number; firstBadId: number | null; verifiedAt: string }
export interface TestExportResult { ok: boolean; message: string }
export type KillSwitchAction = 'engage' | 'release' | 'terminate';
export type ExportFormat = 'ocsf' | 'cef' | 'json';
export interface ExportQuery { format: ExportFormat; from?: string; to?: string; agentId?: string }

/** SSE messages, discriminated by the `event:` name. */
export type StreamMessage =
  | { type: 'hello'; data: Status }
  | { type: 'event'; data: AgentEvent }
  | { type: 'alert'; data: Alert }
  | { type: 'approval'; data: Approval }
  | { type: 'agent'; data: Agent }
  | { type: 'status'; data: Status };
export type StreamType = StreamMessage['type'];
export const STREAM_TYPES: StreamType[] = ['hello', 'event', 'alert', 'approval', 'agent', 'status'];

export type ConnectionState = 'connecting' | 'open' | 'reconnecting' | 'offline';
