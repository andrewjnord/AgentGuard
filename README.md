# AgentGuard for Windows

AgentGuard finds the AI agents on a Windows PC (Claude Code, Cursor, VS Code + Copilot, local models, MCP servers), records what they do, and enforces a YAML policy (allow / log / ask / block), with human approvals and SIEM export.

The product spec lives in the shared AgentGuard spec doc. The local API contract is in [`docs/api.md`](docs/api.md).

## Status

| Area | Path | State |
| --- | --- | --- |
| Core library: policy engine, hash-chained SQLite audit log, OCSF / CEF / Splunk HEC / syslog / JSON exporters, agent discovery and attribution, MCP config scanning and proxy wrapping, Claude Code hook mapping | `src/AgentGuard.Core` | Done, 77 unit tests |
| Default policy and known-hosts allowlist | `policies/` | Done |
| Agent and MCP client signatures | `signatures/agents.yaml` | Done |
| Web dashboard (React + TypeScript, mock mode) | `src/dashboard` | Done; builds into `src/AgentGuard.Service/wwwroot` |
| Windows service: host wiring, full local API (`docs/api.md`), SSE, background workers, demo mode | `src/AgentGuard.Service` | Done, 59 integration tests |
| MCP stdio proxy (`agentguard-mcp-proxy`) | `src/AgentGuard.McpProxy` | Done |
| Claude Code PreToolUse hook (`agentguard-hook`) | `src/AgentGuard.Hook` | Done |
| Admin CLI (`agentguard`) | `src/AgentGuard.Cli` | Done |
| Tray app (WPF + WebView2) | `src/AgentGuard.Tray` | Done (compiles; needs testing on Windows) |
| Proxy, hook, CLI and tray tests | `tests/AgentGuard.Tools.Tests` | 44 tests |
| Endpoint enforcement adapters (telemetry, process control, network blocking) | `src/AgentGuard.Service/Platform/Windows/WindowsEnforcement.cs` | Interfaces and safety guard done; Windows implementations still a placeholder |
| Installer (WiX) and CI (GitHub Actions) | `installer/`, `.github/workflows/` | To do |

## Build

Requires the .NET 8 SDK (the official Microsoft SDK, which includes the Windows Desktop targets) and Node 20+.

```
dotnet test tests/AgentGuard.Core.Tests
cd src/dashboard && npm ci && npm run build     # writes src/AgentGuard.Service/wwwroot
npm run dev:mock                                 # dashboard with in-browser mock data
```
