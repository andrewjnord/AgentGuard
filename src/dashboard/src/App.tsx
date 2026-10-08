import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react';
import { createApi, IS_MOCK, UnauthorizedError, ApiError, type AgentGuardApi, type Status } from './api';
import { getToken, resolveToken, setToken, clearToken } from './api/auth';
import { AppProvider } from './lib/store';
import { useRoute, type Page } from './lib/router';
import { useTheme } from './lib/theme';
import { Shell } from './components/Shell';
import { Connect } from './components/Connect';
import { Toasts } from './components/Toasts';
import { ApprovalPrompt } from './components/ApprovalPrompt';
import { Skeleton } from './components/ui';
import { Overview } from './pages/Overview';

const Agents = lazy(() => import('./pages/Agents'));
const McpServers = lazy(() => import('./pages/McpServers'));
const Timeline = lazy(() => import('./pages/Timeline'));
const Approvals = lazy(() => import('./pages/Approvals'));
const Alerts = lazy(() => import('./pages/Alerts'));
const Policy = lazy(() => import('./pages/Policy'));
const SettingsPage = lazy(() => import('./pages/Settings'));

type Phase =
  | { kind: 'booting' }
  | { kind: 'connect'; reason: 'missing' | 'rejected' | 'unreachable'; busy: boolean }
  | { kind: 'ready'; api: AgentGuardApi; status: Status };

function PageView({ page }: { page: Page }) {
  switch (page) {
    case 'overview': return <Overview />;
    case 'agents': return <Agents />;
    case 'mcp': return <McpServers />;
    case 'timeline': return <Timeline />;
    case 'approvals': return <Approvals />;
    case 'alerts': return <Alerts />;
    case 'policy': return <Policy />;
    case 'settings': return <SettingsPage />;
  }
}

function PageFallback() {
  return (
    <div className="page" aria-busy="true">
      <Skeleton w={220} h={24} />
      <Skeleton w={380} h={12} style={{ marginTop: 10 }} />
      <Skeleton h={320} style={{ marginTop: 24, borderRadius: 10 }} />
    </div>
  );
}

export function App() {
  const [phase, setPhase] = useState<Phase>({ kind: 'booting' });
  const route = useRoute();
  const theme = useTheme();
  const apiRef = useRef<AgentGuardApi | null>(null);

  const onUnauthorized = useCallback(() => {
    clearToken();
    setPhase({ kind: 'connect', reason: 'rejected', busy: false });
  }, []);

  const connect = useCallback(async () => {
    if (!IS_MOCK && !getToken()) { setPhase({ kind: 'connect', reason: 'missing', busy: false }); return; }
    try {
      apiRef.current ??= await createApi(onUnauthorized);
      const status = await apiRef.current.status();
      setPhase({ kind: 'ready', api: apiRef.current, status });
    } catch (e) {
      if (e instanceof UnauthorizedError) return; // onUnauthorized already switched phase
      // Only a 401 means the token is bad; anything else (network error, proxy 5xx, 403 origin) is a reachability problem.
      setPhase({ kind: 'connect', reason: e instanceof ApiError && e.status === 401 ? 'rejected' : 'unreachable', busy: false });
    }
  }, [onUnauthorized]);

  useEffect(() => { resolveToken(); void connect(); }, [connect]);

  if (phase.kind === 'booting') return <div className="boot" aria-busy="true" aria-label="Loading AgentGuard" />;
  if (phase.kind === 'connect') {
    return (
      <Connect reason={phase.reason} busy={phase.busy}
        onSubmit={(t) => { setToken(t); setPhase({ ...phase, busy: true }); void connect(); }} />
    );
  }
  return (
    <AppProvider api={phase.api} initialStatus={phase.status}>
      <Shell page={route.page} theme={theme.resolved} onToggleTheme={theme.toggle}>
        <Suspense fallback={<PageFallback />}>
          <PageView key={route.page} page={route.page} />
        </Suspense>
      </Shell>
      <ApprovalPrompt suppressed={route.page === 'approvals'} />
      <Toasts />
    </AppProvider>
  );
}
