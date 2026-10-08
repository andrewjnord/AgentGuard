// Deterministic seeded data for mock mode. Never imported by the production build path.
import type {
  Agent, AgentEvent, Alert, Approval, EventSourceKind, McpServer, PolicyInfo, Settings, Severity, Verdict,
} from '../types';

export function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function pick<T>(r: () => number, items: readonly T[]): T {
  return items[Math.floor(r() * items.length)];
}

export function fakeHash(r: () => number): string {
  let h = '';
  for (let i = 0; i < 64; i++) h += Math.floor(r() * 16).toString(16);
  return h;
}

const HOME = 'C:\\Users\\dana.whitfield';
const REPO = `${HOME}\\source\\repos\\payments-api`;

export const POLICY_V3 = `# AgentGuard policy
# Rules are evaluated top to bottom; the first match wins.
version: 1
mode: enforce

defaults:
  verdict: log
  approval_timeout: 120s

rules:
  - id: secrets.ssh-keys
    description: Private SSH keys are never readable by agents
    action: file.read
    match:
      path:
        - "~/.ssh/id_*"
        - "~/.ssh/*.pem"
    exclude:
      path: ["~/.ssh/*.pub"]
    verdict: block
    severity: critical

  - id: secrets.cloud-credentials
    description: Cloud CLI credential stores
    action: file.read
    match:
      path:
        - "~/.aws/credentials"
        - "~/.azure/msal_token_cache.*"
        - "~/AppData/Roaming/gcloud/**"
    verdict: block
    severity: high

  - id: secrets.dotenv
    action: [file.read, file.write]
    match:
      path: ["**/.env", "**/.env.*"]
    verdict: ask
    severity: medium

  - id: shell.recursive-delete
    description: Recursive deletes need a human
    action: shell.exec
    match:
      command:
        - "Remove-Item * -Recurse*"
        - "rm -rf *"
        - "rd /s *"
    verdict: ask
    severity: high

  - id: shell.download-exec
    action: shell.exec
    match:
      command:
        - "*iwr * | iex*"
        - "*Invoke-Expression*DownloadString*"
        - "*curl * | sh*"
    verdict: block
    severity: critical

  - id: shell.git-push-force
    action: shell.exec
    match:
      command: ["git push *--force*", "git push * -f*"]
    verdict: ask
    severity: medium

  - id: net.first-contact
    description: Log the first connection to any new host
    action: net.connect
    match:
      first_seen: true
    verdict: log
    severity: low

  - id: net.paste-sites
    action: net.connect
    match:
      host: ["pastebin.com", "*.ngrok-free.app", "transfer.sh"]
    verdict: block
    severity: high

  - id: mcp.postgres-writes
    action: mcp.call
    match:
      tool: ["postgres/execute", "postgres/write_query"]
    verdict: ask
    severity: high

  - id: mcp.github-admin
    action: mcp.call
    match:
      tool: ["github/delete_repository", "github/update_branch_protection"]
    verdict: block
    severity: high

  - id: files.outside-workspace
    action: [file.write, file.delete]
    match:
      outside_workspace: true
    verdict: ask
    severity: medium
`;

export const POLICY_V2 = POLICY_V3
  .replace(/\n  - id: mcp\.github-admin[\s\S]*?severity: high\n/, '\n')
  .replace('verdict: ask\n    severity: high\n\n  - id: shell.download-exec', 'verdict: block\n    severity: high\n\n  - id: shell.download-exec');

export const POLICY_V1 = `# AgentGuard policy (initial)
version: 1
mode: monitor

defaults:
  verdict: log

rules:
  - id: secrets.ssh-keys
    action: file.read
    match:
      path: ["~/.ssh/id_*"]
    verdict: block
    severity: critical

  - id: shell.recursive-delete
    action: shell.exec
    match:
      command: ["Remove-Item * -Recurse*", "rm -rf *"]
    verdict: ask
    severity: high
`;

export function countRules(yaml: string): number {
  return (yaml.match(/^\s*- id:/gm) ?? []).length;
}

export function seedPolicies(now: number): PolicyInfo[] {
  const day = 86400000;
  return [
    { yaml: POLICY_V1, version: 1, appliedAt: new Date(now - 21 * day).toISOString(), appliedBy: 'installer', ruleCount: countRules(POLICY_V1), mode: 'monitor' },
    { yaml: POLICY_V2, version: 2, appliedAt: new Date(now - 9 * day).toISOString(), appliedBy: 'CORP\\dana.whitfield', ruleCount: countRules(POLICY_V2), mode: 'enforce' },
    { yaml: POLICY_V3, version: 3, appliedAt: new Date(now - 2 * day - 3600000 * 5).toISOString(), appliedBy: 'CORP\\dana.whitfield', ruleCount: countRules(POLICY_V3), mode: 'enforce' },
  ];
}

export function seedSettings(): Settings {
  return {
    retentionDays: 30,
    failMode: 'closed',
    autoSuspendOnDetectBlock: true,
    approvalTimeoutSeconds: 120,
    exports: {
      splunk: { enabled: true, url: 'https://splunk-hec.corp.example:8088/services/collector/event', token: '********', index: 'endpoint_ai', sourcetype: 'agentguard:ocsf', verifyTls: true },
      syslog: { enabled: false, host: 'siem-relay.corp.example', port: 6514, protocol: 'tcp' },
      jsonFile: { enabled: true, directory: 'C:\\ProgramData\\AgentGuard\\exports' },
    },
    redaction: { patterns: ['(?i)bearer\\s+[a-z0-9._-]+', 'ghp_[A-Za-z0-9]{36}', 'AKIA[0-9A-Z]{16}', '(?i)password\\s*=\\s*\\S+'] },
  };
}

const off = { hooks: false, mcpProxy: false, firewall: false, processControl: false, fileDetectOnly: false };

export function seedAgents(now: number): Agent[] {
  const h = 3600000;
  const iso = (ms: number) => new Date(now - ms).toISOString();
  const a = (p: Partial<Agent> & Pick<Agent, 'id' | 'kind' | 'name'>): Agent => ({
    exePath: null, publisher: null, signerValid: null, firstSeen: iso(20 * 24 * h), lastSeen: iso(60000),
    trust: 'unknown', running: false, pids: [], networkBlocked: false, enforcement: { ...off },
    eventCount24h: 0, blockedCount24h: 0, mcpServerIds: [], ...p,
  });
  return [
    a({ id: 'claude-code', kind: 'cli', name: 'Claude Code', exePath: `${HOME}\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js`, publisher: 'Anthropic, PBC', signerValid: true, trust: 'allowed', running: true, pids: [14212, 18840], enforcement: { hooks: true, mcpProxy: true, firewall: true, processControl: true, fileDetectOnly: false }, mcpServerIds: ['m-cc-fs', 'm-cc-gh'] }),
    a({ id: 'claude-desktop', kind: 'desktop', name: 'Claude Desktop', exePath: `${HOME}\\AppData\\Local\\AnthropicClaude\\claude.exe`, publisher: 'Anthropic, PBC', signerValid: true, trust: 'allowed', running: true, pids: [9032], enforcement: { hooks: false, mcpProxy: true, firewall: true, processControl: true, fileDetectOnly: true }, mcpServerIds: ['m-cd-fs', 'm-cd-pg'] }),
    a({ id: 'cursor', kind: 'desktop', name: 'Cursor', exePath: `${HOME}\\AppData\\Local\\Programs\\cursor\\Cursor.exe`, publisher: 'Anysphere, Inc.', signerValid: true, trust: 'unknown', running: true, pids: [21456, 21490, 22012], enforcement: { hooks: false, mcpProxy: true, firewall: true, processControl: true, fileDetectOnly: true }, mcpServerIds: ['m-cu-gh', 'm-cu-pg'] }),
    a({ id: 'vscode-copilot', kind: 'ide-extension', name: 'VS Code + Copilot', exePath: `${HOME}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`, publisher: 'Microsoft Corporation', signerValid: true, trust: 'allowed', running: false, pids: [], lastSeen: iso(3.2 * h), enforcement: { hooks: false, mcpProxy: false, firewall: true, processControl: true, fileDetectOnly: true }, mcpServerIds: ['m-vs-fs'] }),
    a({ id: 'ollama', kind: 'local-model', name: 'Ollama', exePath: `${HOME}\\AppData\\Local\\Programs\\Ollama\\ollama.exe`, publisher: 'Ollama Inc.', signerValid: true, trust: 'unknown', running: true, pids: [6640], enforcement: { hooks: false, mcpProxy: false, firewall: true, processControl: true, fileDetectOnly: true } }),
    a({ id: 'mcp:filesystem', kind: 'mcp-server', name: 'filesystem (MCP)', exePath: 'npx @modelcontextprotocol/server-filesystem', publisher: null, signerValid: null, trust: 'allowed', running: true, pids: [15520], enforcement: { hooks: false, mcpProxy: true, firewall: true, processControl: true, fileDetectOnly: false } }),
    a({ id: 'mcp:github', kind: 'mcp-server', name: 'github (MCP)', exePath: 'docker run ghcr.io/github/github-mcp-server', publisher: null, signerValid: null, trust: 'unknown', running: true, pids: [17304], enforcement: { hooks: false, mcpProxy: true, firewall: true, processControl: true, fileDetectOnly: false } }),
    a({ id: 'mcp:postgres', kind: 'mcp-server', name: 'postgres (MCP)', exePath: 'npx @modelcontextprotocol/server-postgres', publisher: null, signerValid: null, trust: 'unknown', running: false, pids: [], lastSeen: iso(5.5 * h), enforcement: { hooks: false, mcpProxy: false, firewall: true, processControl: true, fileDetectOnly: false } }),
    a({ id: 'unknown:python-3824', kind: 'unknown', name: 'python.exe (agent-like)', exePath: `${HOME}\\miniconda3\\python.exe`, publisher: 'Python Software Foundation', signerValid: true, trust: 'unknown', running: false, pids: [], firstSeen: iso(7 * h), lastSeen: iso(6.6 * h), enforcement: { ...off, fileDetectOnly: true } }),
  ];
}

export function seedMcp(now: number): McpServer[] {
  const iso = (ms: number | null) => (ms === null ? null : new Date(now - ms).toISOString());
  const m = 60000;
  const s = (p: Omit<McpServer, 'lastCallAt'> & { last: number | null }): McpServer => {
    const { last, ...rest } = p;
    return { ...rest, lastCallAt: iso(last) };
  };
  const ccCfg = `${HOME}\\.claude.json`;
  const cdCfg = `${HOME}\\AppData\\Roaming\\Claude\\claude_desktop_config.json`;
  const cuCfg = `${HOME}\\.cursor\\mcp.json`;
  const vsCfg = `${REPO}\\.vscode\\mcp.json`;
  return [
    s({ id: 'm-cc-fs', name: 'filesystem', client: 'Claude Code', configPath: ccCfg, scope: 'user', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', `${HOME}\\source\\repos`], url: null, proxied: true, agentId: 'mcp:filesystem', last: 2 * m }),
    s({ id: 'm-cc-gh', name: 'github', client: 'Claude Code', configPath: ccCfg, scope: 'user', transport: 'stdio', command: 'docker', args: ['run', '-i', '--rm', '-e', 'GITHUB_PERSONAL_ACCESS_TOKEN', 'ghcr.io/github/github-mcp-server'], url: null, proxied: true, agentId: 'mcp:github', last: 14 * m }),
    s({ id: 'm-cd-fs', name: 'filesystem', client: 'Claude Desktop', configPath: cdCfg, scope: 'user', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', `${HOME}\\Documents`], url: null, proxied: true, agentId: 'mcp:filesystem', last: 48 * m }),
    s({ id: 'm-cd-pg', name: 'postgres', client: 'Claude Desktop', configPath: cdCfg, scope: 'user', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres', 'postgresql://readonly@localhost:5432/payments'], url: null, proxied: false, agentId: 'mcp:postgres', last: 330 * m }),
    s({ id: 'm-cu-gh', name: 'github', client: 'Cursor', configPath: cuCfg, scope: 'user', transport: 'http', command: null, args: [], url: 'https://api.githubcopilot.com/mcp/', proxied: true, agentId: 'mcp:github', last: 95 * m }),
    s({ id: 'm-cu-pg', name: 'postgres', client: 'Cursor', configPath: cuCfg, scope: 'user', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres', 'postgresql://app@localhost:5432/payments'], url: null, proxied: false, agentId: 'mcp:postgres', last: null }),
    s({ id: 'm-vs-fs', name: 'filesystem', client: 'VS Code', configPath: vsCfg, scope: 'project', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '${workspaceFolder}'], url: null, proxied: false, agentId: 'mcp:filesystem', last: 200 * m }),
  ];
}

interface Template {
  agentId: string; agentName: string; action: string; target: string; verdict: Verdict; severity: Severity;
  source: EventSourceKind; ruleId: string | null; details: Record<string, unknown>; weight: number; pids: number[];
}

const T = (agentId: string, agentName: string, pids: number[]) =>
  (action: string, target: string, verdict: Verdict, severity: Severity, source: EventSourceKind, ruleId: string | null, details: Record<string, unknown>, weight: number): Template =>
    ({ agentId, agentName, action, target, verdict, severity, source, ruleId, details, weight, pids });

const cc = T('claude-code', 'Claude Code', [14212, 18840]);
const cd = T('claude-desktop', 'Claude Desktop', [9032]);
const cu = T('cursor', 'Cursor', [21456, 21490]);
const vs = T('vscode-copilot', 'VS Code + Copilot', [11208]);
const ol = T('ollama', 'Ollama', [6640]);
const fs = T('mcp:filesystem', 'filesystem (MCP)', [15520]);
const gh = T('mcp:github', 'github (MCP)', [17304]);
const pg = T('mcp:postgres', 'postgres (MCP)', [19980]);

export const TEMPLATES: Template[] = [
  cc('file.read', `${REPO}\\src\\Controllers\\RefundController.cs`, 'allow', 'info', 'hook', null, { tool: 'Read', bytes: 8421, cwd: REPO }, 30),
  cc('file.read', `${REPO}\\src\\Services\\LedgerService.cs`, 'allow', 'info', 'hook', null, { tool: 'Read', bytes: 15002, cwd: REPO }, 22),
  cc('file.write', `${REPO}\\src\\Services\\LedgerService.cs`, 'log', 'low', 'hook', null, { tool: 'Edit', linesChanged: 34, cwd: REPO }, 14),
  cc('file.write', `${REPO}\\tests\\LedgerServiceTests.cs`, 'log', 'low', 'hook', null, { tool: 'Write', linesChanged: 112, cwd: REPO }, 8),
  cc('shell.exec', 'dotnet test --filter Category=Ledger', 'allow', 'info', 'hook', null, { tool: 'Bash', shell: 'pwsh', cwd: REPO, exitCode: 0, durationMs: 18233 }, 12),
  cc('shell.exec', 'git status --porcelain', 'allow', 'info', 'hook', null, { tool: 'Bash', shell: 'pwsh', cwd: REPO, exitCode: 0 }, 10),
  cc('shell.exec', 'git diff --stat HEAD~1', 'allow', 'info', 'hook', null, { tool: 'Bash', shell: 'pwsh', cwd: REPO, exitCode: 0 }, 6),
  cc('shell.exec', 'Remove-Item -Recurse -Force .\\bin, .\\obj', 'ask', 'high', 'hook', 'shell.recursive-delete', { tool: 'Bash', shell: 'pwsh', cwd: REPO, reason: 'Matched pattern "Remove-Item * -Recurse*"' }, 3),
  cc('shell.exec', 'Remove-Item -Recurse -Force C:\\Users\\dana.whitfield\\source\\repos\\payments-api\\.git\\refs', 'ask', 'high', 'hook', 'shell.recursive-delete', { tool: 'Bash', shell: 'pwsh', cwd: REPO, reason: 'Matched pattern "Remove-Item * -Recurse*"' }, 1),
  cc('file.read', `${HOME}\\.ssh\\id_ed25519`, 'block', 'critical', 'hook', 'secrets.ssh-keys', { tool: 'Read', cwd: REPO, reason: 'Private SSH key', userPrompt: 'set up deploy to staging' }, 2),
  cc('file.read', `${REPO}\\.env`, 'ask', 'medium', 'hook', 'secrets.dotenv', { tool: 'Read', cwd: REPO }, 2),
  cc('net.connect', 'api.anthropic.com:443', 'allow', 'info', 'etw', null, { remoteIp: '160.79.104.10', protocol: 'tcp', bytesOut: 48211 }, 10),
  cc('net.connect', 'registry.npmjs.org:443', 'log', 'low', 'etw', 'net.first-contact', { remoteIp: '104.16.24.35', protocol: 'tcp', firstSeen: true }, 1),
  cc('mcp.call', 'github/create_pull_request', 'allow', 'info', 'mcp-proxy', null, { server: 'github', tool: 'create_pull_request', args: { repo: 'corp/payments-api', head: 'fix/ledger-rounding', base: 'main' } }, 2),
  cc('mcp.call', 'filesystem/read_text_file', 'allow', 'info', 'mcp-proxy', null, { server: 'filesystem', tool: 'read_text_file', args: { path: `${REPO}\\README.md` } }, 6),
  cc('process.start', 'pwsh.exe -NoProfile -Command dotnet build', 'allow', 'info', 'etw', null, { parentPid: 14212, childPid: 23310, integrity: 'medium' }, 6),
  cc('shell.exec', 'git push origin fix/ledger-rounding --force', 'ask', 'medium', 'hook', 'shell.git-push-force', { tool: 'Bash', shell: 'pwsh', cwd: REPO }, 1),

  cd('mcp.call', 'filesystem/list_directory', 'allow', 'info', 'mcp-proxy', null, { server: 'filesystem', tool: 'list_directory', args: { path: `${HOME}\\Documents\\Q3 board` } }, 8),
  cd('mcp.call', 'filesystem/read_text_file', 'allow', 'info', 'mcp-proxy', null, { server: 'filesystem', tool: 'read_text_file', args: { path: `${HOME}\\Documents\\Q3 board\\notes.md` } }, 6),
  cd('file.read', `${HOME}\\.aws\\credentials`, 'block', 'high', 'etw', 'secrets.cloud-credentials', { detectOnly: true, accessMask: 'GENERIC_READ', note: 'Observed via ETW; read could not be prevented' }, 1),
  cd('net.connect', 'claude.ai:443', 'allow', 'info', 'etw', null, { remoteIp: '160.79.104.10', protocol: 'tcp' }, 8),

  cu('file.read', `${REPO}\\src\\Program.cs`, 'allow', 'info', 'etw', null, { detectOnly: true }, 14),
  cu('file.write', `${REPO}\\src\\Models\\Refund.cs`, 'log', 'low', 'etw', null, { detectOnly: true, bytes: 2210 }, 8),
  cu('file.read', `${HOME}\\.ssh\\id_ed25519`, 'block', 'critical', 'etw', 'secrets.ssh-keys', { detectOnly: true, accessMask: 'GENERIC_READ', autoSuspended: true }, 1),
  cu('shell.exec', 'npm install --save left-pad@1.3.0', 'log', 'low', 'etw', null, { shell: 'cmd', cwd: `${HOME}\\source\\repos\\web-console` }, 3),
  cu('net.connect', 'api2.cursor.sh:443', 'allow', 'info', 'etw', null, { remoteIp: '34.117.59.81', protocol: 'tcp' }, 10),
  cu('net.connect', 'a9f3-81-2-69-142.ngrok-free.app:443', 'block', 'high', 'etw', 'net.paste-sites', { remoteIp: '3.124.67.191', protocol: 'tcp', firewallRule: 'AgentGuard-cursor-out' }, 1),
  cu('mcp.call', 'postgres/query', 'log', 'low', 'etw', null, { server: 'postgres', tool: 'query', sql: 'SELECT id, amount FROM refunds ORDER BY created_at DESC LIMIT 50', proxied: false }, 3),

  vs('file.read', `${REPO}\\src\\Controllers\\RefundController.cs`, 'allow', 'info', 'etw', null, { detectOnly: true }, 8),
  vs('net.connect', 'api.githubcopilot.com:443', 'allow', 'info', 'etw', null, { remoteIp: '140.82.113.21', protocol: 'tcp' }, 8),
  vs('file.write', `${REPO}\\src\\Controllers\\RefundController.cs`, 'log', 'low', 'etw', null, { detectOnly: true, bytes: 9822 }, 3),

  ol('net.connect', 'registry.ollama.ai:443', 'log', 'low', 'etw', 'net.first-contact', { remoteIp: '104.21.75.227', protocol: 'tcp', firstSeen: true }, 1),
  ol('file.write', `${HOME}\\.ollama\\models\\blobs\\sha256-6a0746a1ec1a`, 'log', 'info', 'etw', null, { detectOnly: true, bytes: 4920000000 }, 2),
  ol('process.start', 'ollama.exe runner --model qwen2.5-coder:14b --port 61822', 'allow', 'info', 'etw', null, { parentPid: 6640, childPid: 24008 }, 3),

  fs('mcp.call', 'filesystem/write_file', 'log', 'low', 'mcp-proxy', null, { server: 'filesystem', tool: 'write_file', args: { path: `${REPO}\\docs\\refunds.md` } }, 4),
  fs('mcp.call', 'filesystem/move_file', 'ask', 'medium', 'mcp-proxy', 'files.outside-workspace', { server: 'filesystem', tool: 'move_file', args: { source: `${REPO}\\build.log`, destination: 'C:\\Windows\\Temp\\build.log' } }, 1),
  gh('mcp.call', 'github/list_issues', 'allow', 'info', 'mcp-proxy', null, { server: 'github', tool: 'list_issues', args: { repo: 'corp/payments-api', state: 'open' } }, 5),
  gh('mcp.call', 'github/delete_repository', 'block', 'high', 'mcp-proxy', 'mcp.github-admin', { server: 'github', tool: 'delete_repository', args: { repo: 'corp/payments-api-sandbox' } }, 1),
  gh('net.connect', 'api.github.com:443', 'allow', 'info', 'etw', null, { remoteIp: '140.82.112.6', protocol: 'tcp' }, 4),
  pg('mcp.call', 'postgres/query', 'allow', 'info', 'mcp-proxy', null, { server: 'postgres', tool: 'query', sql: 'SELECT count(*) FROM ledger_entries WHERE posted = false' }, 4),
  pg('mcp.call', 'postgres/execute', 'ask', 'high', 'mcp-proxy', 'mcp.postgres-writes', { server: 'postgres', tool: 'execute', sql: "UPDATE refunds SET status = 'approved' WHERE amount < 50" }, 1),
];

const totalWeight = TEMPLATES.reduce((s, t) => s + t.weight, 0);
export function pickTemplate(r: () => number): Template {
  let x = r() * totalWeight;
  for (const t of TEMPLATES) { x -= t.weight; if (x <= 0) return t; }
  return TEMPLATES[0];
}

/** Activity per hour roughly follows a working day (peaks late morning and mid afternoon). */
function hourWeight(hourOfDay: number): number {
  const work = Math.exp(-((hourOfDay - 11) ** 2) / 10) + 0.9 * Math.exp(-((hourOfDay - 15.5) ** 2) / 6);
  return 0.08 + work;
}

export function makeEvent(r: () => number, id: number, tsMs: number, t: Template, enforcedMode: boolean): AgentEvent {
  const detectOnly = t.details.detectOnly === true;
  const enforced = enforcedMode && !detectOnly && (t.verdict === 'block' || t.verdict === 'ask');
  return {
    id, ts: new Date(tsMs).toISOString(), agentId: t.agentId, agentName: t.agentName,
    pid: t.pids.length ? pick(r, t.pids) : null, action: t.action, target: t.target, details: { ...t.details },
    verdict: t.verdict, ruleId: t.ruleId, severity: t.severity, source: t.source, enforced, hash: fakeHash(r),
  };
}

export function seedEvents(now: number): AgentEvent[] {
  const r = rng(20261008);
  const out: AgentEvent[] = [];
  const startMs = now - 24 * 3600000;
  const nowHour = new Date(now).getHours();
  // Distribute ~420 events across 24 hourly buckets.
  const weights = Array.from({ length: 24 }, (_, i) => hourWeight((nowHour - 23 + i + 24) % 24));
  const wsum = weights.reduce((a, b) => a + b, 0);
  let id = 48210;
  weights.forEach((w, i) => {
    const n = Math.round((w / wsum) * 420);
    for (let k = 0; k < n; k++) {
      const ts = startMs + i * 3600000 + r() * 3600000;
      if (ts > now - 150000) continue; // leave room for the backdated pending approvals
      out.push(makeEvent(r, 0, ts, pickTemplate(r), true));
    }
  });
  // Discovery and system events.
  const sys = (ms: number, agentId: string, agentName: string, action: string, target: string, sev: Severity, source: EventSourceKind, details: Record<string, unknown>) =>
    out.push({ id: 0, ts: new Date(now - ms).toISOString(), agentId, agentName, pid: null, action, target, details, verdict: 'log', ruleId: null, severity: sev, source, enforced: false, hash: fakeHash(r) });
  sys(7 * 3600000, 'unknown:python-3824', 'python.exe (agent-like)', 'agent.discovered', `${HOME}\\miniconda3\\python.exe agent_loop.py`, 'medium', 'discovery', { heuristic: 'LLM API + shell spawn pattern', score: 0.82 });
  sys(6.6 * 3600000, 'unknown:python-3824', 'python.exe (agent-like)', 'agent.exited', 'pid 3824', 'info', 'discovery', { exitCode: 0 });
  sys(19 * 3600000, 'system', 'AgentGuard', 'system', 'Service started', 'info', 'system', { version: '0.9.2' });
  sys(5.5 * 3600000, 'mcp:postgres', 'postgres (MCP)', 'agent.exited', 'pid 19980', 'info', 'discovery', { exitCode: 0 });
  sys(3.2 * 3600000, 'vscode-copilot', 'VS Code + Copilot', 'agent.exited', 'pid 11208', 'info', 'discovery', { exitCode: 0 });

  out.sort((a, b) => a.ts.localeCompare(b.ts));
  for (const e of out) e.id = id++;
  return out;
}

export function seedAlerts(events: AgentEvent[]): Alert[] {
  const r = rng(77);
  const alerts: Alert[] = [];
  let id = 900;
  const titleFor = (e: AgentEvent) => {
    if (e.ruleId === 'secrets.ssh-keys') return `${e.agentName} tried to read a private SSH key`;
    if (e.ruleId === 'secrets.cloud-credentials') return `${e.agentName} read cloud credentials (detect-only)`;
    if (e.ruleId === 'net.paste-sites') return `${e.agentName} connected to a tunnelling host`;
    if (e.ruleId === 'mcp.github-admin') return 'GitHub repository deletion was blocked';
    if (e.ruleId === 'shell.recursive-delete') return 'Recursive delete requested';
    if (e.action === 'agent.discovered') return 'Unrecognised agent-like process discovered';
    return `${e.ruleId ?? e.action} matched`;
  };
  for (const e of events) {
    const notable = e.verdict === 'block' || e.action === 'agent.discovered' || (e.ruleId === 'shell.recursive-delete' && r() < 0.5);
    if (!notable) continue;
    alerts.push({
      id: id++, eventId: e.id, ts: e.ts, severity: e.severity === 'info' ? 'medium' : e.severity,
      status: 'open', title: titleFor(e), agentId: e.agentId, agentName: e.agentName,
      action: e.action, target: e.target, ruleId: e.ruleId,
    });
  }
  // Older ones are triaged.
  alerts.forEach((a, i) => { if (i < alerts.length - 6) a.status = r() < 0.6 ? 'closed' : 'acked'; });
  return alerts.reverse();
}

export function seedApprovalHistory(events: AgentEvent[]): Approval[] {
  const r = rng(5150);
  return events.filter((e) => e.verdict === 'ask').map((e, i) => {
    const req = Date.parse(e.ts);
    const roll = r();
    const decision: Approval['decision'] = roll < 0.5 ? 'allow_once' : roll < 0.65 ? 'allow_always' : roll < 0.88 ? 'deny' : 'timeout';
    const status: Approval['status'] = decision === 'deny' ? 'denied' : decision === 'timeout' ? 'expired' : 'allowed';
    return {
      id: `apr_${(e.id * 7919).toString(36)}${i}`, eventId: e.id, requestedAt: e.ts, expiresAt: new Date(req + 120000).toISOString(),
      agentId: e.agentId, agentName: e.agentName, action: e.action, target: e.target, details: e.details, ruleId: e.ruleId,
      status, decision, decidedAt: new Date(req + (decision === 'timeout' ? 120000 : 4000 + r() * 40000)).toISOString(),
      decidedBy: decision === 'timeout' ? null : pick(r, ['dashboard', 'tray', 'tray']),
    };
  }).reverse();
}
