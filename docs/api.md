# AgentGuard Local API (v1)

The AgentGuard service exposes a JSON API on `http://127.0.0.1:47823`. The dashboard is served from the same origin at `/`.

All JSON uses camelCase. Timestamps are ISO-8601 UTC strings (`2026-10-08T22:31:04.123Z`).

## Authentication

| Endpoint group | Auth |
| --- | --- |
| `POST /api/v1/decide`, `GET /api/v1/health` | None (any local process may ask for a verdict; it grants no control) |
| Everything else under `/api/v1` | Header `X-AgentGuard-Token: <token>`; for `EventSource` and download links, query string `?token=<token>` |

The dashboard obtains its token in this order:

1. `window.__AGENTGUARD_TOKEN__` (injected by the tray app's WebView2 host)
2. URL fragment `#token=<token>` (then removed from the address bar)
3. `sessionStorage["agentguard.token"]`

If no token is available, or a request returns 401, the dashboard shows a "Open AgentGuard from the tray icon" screen with a field to paste a token.

Requests that carry an `Origin` header other than the service's own origin are rejected with 403.

## Enumerations

- `AgentKind`: `cli` | `desktop` | `ide-extension` | `local-model` | `mcp-server` | `unknown`
- `Trust`: `unknown` | `allowed` | `blocked`
- `Verdict`: `allow` | `log` | `ask` | `block`
- `Severity`: `info` | `low` | `medium` | `high` | `critical`
- `Mode`: `monitor` | `enforce` | `strict`
- `Action` (open set): `process.start`, `shell.exec`, `file.read`, `file.write`, `file.delete`, `net.connect`, `mcp.call`, `agent.discovered`, `agent.exited`, `approval.decided`, `policy.changed`, `killswitch`, `system`
- `EventSource`: `hook` | `mcp-proxy` | `etw` | `discovery` | `system` | `demo`

## Types

```ts
interface Status {
  version: string;
  mode: Mode;
  platform: string;                 // "windows" | "linux" | ...
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
  capabilities: { etw: boolean; firewall: boolean; processControl: boolean; hooks: boolean; mcpProxy: boolean };
}

interface Agent {
  id: string;                       // e.g. "claude-code", "cursor", "mcp:filesystem"
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
  enforcement: { hooks: boolean; mcpProxy: boolean; firewall: boolean; processControl: boolean; fileDetectOnly: boolean };
  eventCount24h: number;
  blockedCount24h: number;
  mcpServerIds: string[];
}

interface McpServer {
  id: string;                       // stable hash of client + configPath + name
  name: string;
  client: string;                   // "Claude Desktop" | "Claude Code" | "Cursor" | "VS Code" | "Windsurf"
  configPath: string;
  scope: "user" | "project";
  transport: "stdio" | "http";
  command: string | null;
  args: string[];
  url: string | null;
  proxied: boolean;
  agentId: string;                  // "mcp:<name>"
  lastCallAt: string | null;
}

interface AgentEvent {
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
  source: EventSource;
  enforced: boolean;                // true when the verdict was actually applied (hard block / hold)
  hash: string;
}

interface Alert {
  id: number; eventId: number; ts: string; severity: Severity;
  status: "open" | "acked" | "closed";
  title: string; agentId: string; agentName: string; action: string; target: string; ruleId: string | null;
}

interface Approval {
  id: string; eventId: number; requestedAt: string; expiresAt: string;
  agentId: string; agentName: string; action: string; target: string;
  details: Record<string, unknown>; ruleId: string | null;
  status: "pending" | "allowed" | "denied" | "expired";
  decision: "allow_once" | "allow_always" | "deny" | "timeout" | null;
  decidedAt: string | null; decidedBy: string | null;
}

interface PolicyInfo { yaml: string; version: number; appliedAt: string; appliedBy: string; ruleCount: number; mode: Mode }
interface PolicyValidation { ok: boolean; ruleCount: number; errors: { line: number | null; column: number | null; message: string }[] }

interface Settings {
  retentionDays: number;
  failMode: "closed" | "open";
  autoSuspendOnDetectBlock: boolean;
  approvalTimeoutSeconds: number;
  exports: {
    splunk:  { enabled: boolean; url: string; token: string | null; index: string; sourcetype: string; verifyTls: boolean };
    syslog:  { enabled: boolean; host: string; port: number; protocol: "udp" | "tcp" };
    jsonFile:{ enabled: boolean; directory: string };
  };
  redaction: { patterns: string[] };
}
// On GET, splunk.token is "********" when set, null when unset. On PUT, sending "********" keeps the stored token.
```

## Endpoints

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | – | `{ ok: true, version }` |
| GET | `/api/v1/status` | – | `Status` |
| PUT | `/api/v1/mode` | `{ mode }` | `Status` |
| GET | `/api/v1/stats/activity?hours=24` | – | `{ buckets: { ts: string; total: number; blocked: number; asked: number }[]; topAgents: { agentId: string; agentName: string; total: number; blocked: number }[] }` (hourly buckets, oldest first) |
| GET | `/api/v1/agents` | – | `Agent[]` |
| GET | `/api/v1/agents/{id}` | – | `Agent` |
| PUT | `/api/v1/agents/{id}/trust` | `{ trust }` | `Agent` |
| PUT | `/api/v1/agents/{id}/network` | `{ blocked: boolean }` | `Agent` |
| POST | `/api/v1/agents/{id}/suspend` | – | `{ affected: number }` |
| POST | `/api/v1/agents/{id}/resume` | – | `{ affected: number }` |
| POST | `/api/v1/agents/{id}/terminate` | – | `{ affected: number }` |
| POST | `/api/v1/killswitch` | `{ action: "engage" \| "release" \| "terminate" }` | `Status` |
| GET | `/api/v1/mcp` | – | `McpServer[]` |
| PUT | `/api/v1/mcp/{id}/proxy` | `{ enabled: boolean }` | `McpServer` |
| POST | `/api/v1/mcp/rescan` | – | `McpServer[]` |
| GET | `/api/v1/events?agentId=&action=&verdict=&severity=&source=&q=&from=&to=&before=&limit=100` | – | `{ items: AgentEvent[]; nextBefore: number \| null }` (newest first; `before` = page cursor) |
| GET | `/api/v1/events/{id}` | – | `AgentEvent` |
| GET | `/api/v1/alerts?status=open` | – | `Alert[]` (newest first) |
| PUT | `/api/v1/alerts/{id}` | `{ status }` | `Alert` |
| GET | `/api/v1/approvals?status=pending` | – | `Approval[]` |
| POST | `/api/v1/approvals/{id}` | `{ decision: "allow_once" \| "allow_always" \| "deny" }` | `Approval` |
| GET | `/api/v1/policy` | – | `PolicyInfo` |
| POST | `/api/v1/policy/validate` | `{ yaml }` | `PolicyValidation` |
| PUT | `/api/v1/policy` | `{ yaml }` | `PolicyInfo`, or 400 with `PolicyValidation` |
| GET | `/api/v1/policy/history` | – | `{ version: number; appliedAt: string; appliedBy: string; ruleCount: number }[]` |
| GET | `/api/v1/policy/history/{version}` | – | `PolicyInfo` |
| GET | `/api/v1/settings` | – | `Settings` |
| PUT | `/api/v1/settings` | `Settings` | `Settings` |
| POST | `/api/v1/settings/test-export` | `{ target: "splunk" \| "syslog" \| "jsonFile" }` | `{ ok: boolean; message: string }` |
| POST | `/api/v1/integrity/verify` | – | `{ ok: boolean; checked: number; firstBadId: number \| null; verifiedAt: string }` |
| GET | `/api/v1/export?format=ocsf\|cef\|json&from=&to=&agentId=&token=` | – | file download (`application/x-ndjson` or `text/plain`) |
| GET | `/api/v1/stream?token=` | – | Server-Sent Events, see below |
| POST | `/api/v1/decide` | `DecideRequest` | `DecideResponse` |

### Server-Sent Events (`/api/v1/stream`)

Each message has an `event:` name and a JSON `data:` line.

| event | data |
| --- | --- |
| `hello` | `Status` |
| `event` | `AgentEvent` |
| `alert` | `Alert` |
| `approval` | `Approval` (sent on creation and on every status change) |
| `agent` | `Agent` (on discovery, exit, trust or network change) |
| `status` | `Status` (on mode change, kill switch, every 10 s) |

### Decide (used by the MCP proxy and hooks CLI)

```ts
interface DecideRequest {
  agentId: string;            // "claude-code", "mcp:github"
  agentName?: string;
  pid?: number;
  action: string;             // "shell.exec", "file.read", "mcp.call", ...
  target: string;             // command line, path, "server/tool", host
  details?: Record<string, unknown>;
  source: "hook" | "mcp-proxy";
  userProfile?: string;       // home directory of the calling user, for ~ expansion
  cwd?: string;
  wait?: boolean;             // default true: hold until an "ask" is decided or times out
}
interface DecideResponse {
  verdict: "allow" | "block";  // final, after any approval
  policyVerdict: Verdict;      // what the rule said
  ruleId: string | null;
  reason: string;
  eventId: number;
  approvalId: string | null;
}
```
