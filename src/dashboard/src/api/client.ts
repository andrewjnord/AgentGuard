import type {
  ActivityStats, Agent, AgentEvent, Alert, AlertStatus, Approval, ApprovalDecision, ConnectionState,
  EventPage, EventQuery, ExportQuery, ExportTarget, IntegrityResult, KillSwitchAction, McpServer, Mode,
  PolicyHistoryEntry, PolicyInfo, PolicyValidation, Settings, Status, StreamMessage, TestExportResult, Trust,
} from './types';

/** Everything the dashboard needs from the service. Implemented by HttpApi and (in mock builds) MockApi. */
export interface AgentGuardApi {
  readonly isMock: boolean;
  health(): Promise<{ ok: boolean; version: string }>;
  status(): Promise<Status>;
  setMode(mode: Mode): Promise<Status>;
  activity(hours?: number): Promise<ActivityStats>;

  agents(): Promise<Agent[]>;
  agent(id: string): Promise<Agent>;
  setTrust(id: string, trust: Trust): Promise<Agent>;
  setNetwork(id: string, blocked: boolean): Promise<Agent>;
  suspend(id: string): Promise<{ affected: number }>;
  resume(id: string): Promise<{ affected: number }>;
  terminate(id: string): Promise<{ affected: number }>;
  killSwitch(action: KillSwitchAction): Promise<Status>;

  mcpServers(): Promise<McpServer[]>;
  setMcpProxy(id: string, enabled: boolean): Promise<McpServer>;
  rescanMcp(): Promise<McpServer[]>;

  events(query: EventQuery): Promise<EventPage>;
  event(id: number): Promise<AgentEvent>;

  alerts(status?: AlertStatus): Promise<Alert[]>;
  setAlertStatus(id: number, status: AlertStatus): Promise<Alert>;

  approvals(status?: Approval['status']): Promise<Approval[]>;
  decide(id: string, decision: ApprovalDecision): Promise<Approval>;

  policy(): Promise<PolicyInfo>;
  validatePolicy(yaml: string): Promise<PolicyValidation>;
  /** Resolves with PolicyInfo; rejects with PolicyRejectedError (carrying the validation) on 400. */
  applyPolicy(yaml: string): Promise<PolicyInfo>;
  policyHistory(): Promise<PolicyHistoryEntry[]>;
  policyVersion(version: number): Promise<PolicyInfo>;

  settings(): Promise<Settings>;
  saveSettings(settings: Settings): Promise<Settings>;
  testExport(target: ExportTarget): Promise<TestExportResult>;

  verifyIntegrity(): Promise<IntegrityResult>;
  /** Triggers a file download for the given export. */
  download(query: ExportQuery): Promise<void>;

  /** Live stream. Returns an unsubscribe function. */
  subscribe(onMessage: (m: StreamMessage) => void, onState: (s: ConnectionState) => void): () => void;
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export class UnauthorizedError extends ApiError {
  constructor() { super(401, 'The service rejected the access token.'); this.name = 'UnauthorizedError'; }
}

export class PolicyRejectedError extends ApiError {
  readonly validation: PolicyValidation;
  constructor(validation: PolicyValidation) {
    super(400, 'Policy rejected', validation);
    this.name = 'PolicyRejectedError';
    this.validation = validation;
  }
}

export function isPolicyValidation(v: unknown): v is PolicyValidation {
  return !!v && typeof v === 'object' && 'ok' in v && Array.isArray((v as PolicyValidation).errors);
}
