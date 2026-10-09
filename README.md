# AgentGuard for Windows

AgentGuard finds the AI agents on a Windows PC (Claude Code, Cursor, VS Code + Copilot, local models, MCP servers), records what they do, and enforces a YAML policy (allow / log / ask / block), with human approvals and SIEM export.

The product spec lives in the shared AgentGuard spec doc. The local API contract is in [`docs/api.md`](docs/api.md).

## Status

| Area | Path | State |
| --- | --- | --- |
| Core library: policy engine, hash-chained SQLite audit log, OCSF / CEF / Splunk HEC / syslog / JSON exporters, agent discovery and attribution, MCP config scanning and proxy wrapping, Claude Code hook mapping | `src/AgentGuard.Core` | Done, 77 unit tests passing |
| Default policy and known-hosts allowlist | `policies/` | Done |
| Agent and MCP client signatures | `signatures/agents.yaml` | Done |
| Web dashboard (React + TypeScript, mock mode) | `src/dashboard` | Done; builds into `src/AgentGuard.Service/wwwroot` |
| Windows service: options, policy/settings managers, event pipeline, approvals, kill switch (decision level), MCP proxy toggling, token/origin security, tray token pipe, status DTOs | `src/AgentGuard.Service` | Partial: no `Program.cs` wiring or API endpoints yet |
| Service API endpoints, SSE, background workers, demo mode | `src/AgentGuard.Service/Api` | To do (see `docs/api.md`) |
| MCP stdio proxy (`agentguard-mcp-proxy`) | — | To do |
| Claude Code PreToolUse hook (`agentguard-hook`) | — | To do |
| Admin CLI (`agentguard`) | — | To do |
| Tray app (WPF + WebView2) | `src/AgentGuard.Tray` | Project file only |
| Endpoint enforcement adapters (telemetry, process control, network blocking) | `src/AgentGuard.Service/Platform/Platform.cs` | Interface only (`IEnforcementAdapters`, reports unavailable) |
| Installer (WiX) and CI (GitHub Actions) | `installer/`, `.github/workflows/` | To do |

## Build

Requires the .NET 8 SDK (the official Microsoft SDK, which includes the Windows Desktop targets) and Node 20+.

```
dotnet test tests/AgentGuard.Core.Tests
cd src/dashboard && npm ci && npm run build     # writes src/AgentGuard.Service/wwwroot
npm run dev:mock                                 # dashboard with in-browser mock data
```
