// Token resolution, in the order specified by docs/api.md:
//   1. window.__AGENTGUARD_TOKEN__ (WebView2 host injection)
//   2. URL fragment #token=<token>  (removed from the address bar afterwards)
//   3. sessionStorage["agentguard.token"]

declare global {
  interface Window { __AGENTGUARD_TOKEN__?: string }
}

const STORAGE_KEY = 'agentguard.token';

function readSession(): string | null {
  try { return window.sessionStorage.getItem(STORAGE_KEY); } catch { return null; }
}
function writeSession(token: string | null): void {
  try {
    if (token) window.sessionStorage.setItem(STORAGE_KEY, token);
    else window.sessionStorage.removeItem(STORAGE_KEY);
  } catch { /* storage unavailable: token lives in memory only */ }
}

function takeFragmentToken(): string | null {
  const hash = window.location.hash;
  // Accept "#token=abc" and "#/route&token=abc" without mangling the rest of the fragment.
  const m = hash.match(/(^#|[&?])token=([^&]*)/);
  if (!m) return null;
  let token: string;
  try { token = decodeURIComponent(m[2]); } catch { token = m[2]; }
  const rest = hash.replace(m[0], m[1] === '#' ? '#' : '').replace(/^#&/, '#');
  const url = window.location.pathname + window.location.search + (rest.length > 1 ? rest : '');
  try { window.history.replaceState(window.history.state, '', url); } catch { /* ignore */ }
  return token || null;
}

let current: string | null = null;

/** Resolve the token once at startup. Persists fragment/injected tokens to sessionStorage so reloads keep working. */
export function resolveToken(): string | null {
  const injected = typeof window.__AGENTGUARD_TOKEN__ === 'string' && window.__AGENTGUARD_TOKEN__.trim()
    ? window.__AGENTGUARD_TOKEN__.trim() : null;
  // Always strip a fragment token from the URL, even if an injected token wins.
  const fragment = takeFragmentToken();
  const token = injected ?? fragment ?? readSession();
  if (token && token !== readSession()) writeSession(token);
  current = token;
  return token;
}

export function getToken(): string | null { return current; }

export function setToken(token: string | null): void {
  current = token && token.trim() ? token.trim() : null;
  writeSession(current);
}

export function clearToken(): void { setToken(null); }
