# AgentGuard dashboard

The web console served by `AgentGuard.Service` at `http://127.0.0.1:47823/`. It is built with Vite, React 18 and strict TypeScript, using plain CSS and `lucide-react` icons. It has no runtime CDN dependencies, so it works fully offline.

## Scripts

| Script | What it does |
| --- | --- |
| `npm run dev` | Dev server on :5173. `/api` is proxied to the service at `http://127.0.0.1:47823`. |
| `npm run dev:mock` | Dev server with the in-browser mock API. No service is needed. |
| `npm run build` | Typechecks, then builds to `../AgentGuard.Service/wwwroot` (emptied first). |
| `npm run build:mock` | Typechecks, then builds the mock variant to `dist-mock/`. It never touches wwwroot. |
| `npm run preview` / `npm run preview:mock` | Serve the last build (`preview:mock` serves `dist-mock`). |
| `npm run typecheck` | `tsc -b` only. |

## Mock mode

`--mode mock` loads `.env.mock` (`VITE_MOCK=1`). `src/api/index.ts` then dynamically imports `src/api/mock/mockApi.ts`, which implements the whole `AgentGuardApi` interface in memory:

- Seeded data: 9 agents (Claude Code, Claude Desktop, Cursor, VS Code + Copilot, Ollama, the filesystem/github/postgres MCP servers, and an unrecognised python agent), 7 MCP server configs, about 420 events over 24 hours, alerts, approval history, 3 policy versions and settings.
- A timer emits live `event`, `alert`, `approval` and `status` messages through the same `subscribe()` interface the SSE client uses, so live behaviour, including the global approval prompt, can be exercised.

The import is guarded by `import.meta.env.VITE_MOCK === '1'`, which is a compile-time constant. In a normal build the branch is dead code and the mock module is not emitted at all.

## Auth

The token is resolved as `docs/api.md` specifies: `window.__AGENTGUARD_TOKEN__`, then `#token=` (removed from the address bar with `history.replaceState`), then `sessionStorage["agentguard.token"]`. A missing token or any 401 shows the Connect screen. REST calls send `X-AgentGuard-Token`. EventSource and export downloads use `?token=`.

## Layout

```
src/
  api/          types.ts (contract types), client.ts (interface + errors), http.ts (fetch + SSE), auth.ts, mock/
  components/   Shell (nav, mode switch, kill switch), ActivityChart (SVG), YamlEditor, ApprovalCard/Prompt, ui.tsx
  pages/        Overview, Agents, McpServers, Timeline, Approvals, Alerts, Policy, Settings
  lib/          store (context + live stream bus), router (hash routes), theme, format, hooks
  styles/       tokens.css (light/dark tokens), base.css, pages.css
```

Routes are hash-based (`#/timeline?verdict=block`), so the service only has to serve `index.html` at `/`.
