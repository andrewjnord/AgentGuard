import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { AgentGuardApi } from '../api/client';
import type { Approval, ConnectionState, Status, StreamMessage } from '../api/types';

export interface Toast { id: number; kind: 'ok' | 'error' | 'info'; text: string }
type Listener = (m: StreamMessage) => void;

interface AppCtx {
  api: AgentGuardApi;
  status: Status | null;
  setStatus: (s: Status) => void;
  conn: ConnectionState;
  /** Subscribe to live stream messages. Returns unsubscribe. */
  onStream: (l: Listener) => () => void;
  toasts: Toast[];
  toast: (text: string, kind?: Toast['kind']) => void;
  dismissToast: (id: number) => void;
  /** Pending approvals, kept live from the stream so any page (and the global prompt) can use them. */
  pending: Approval[];
  refreshPending: () => void;
}

const Ctx = createContext<AppCtx | null>(null);

export function useApp(): AppCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useApp outside AppProvider');
  return c;
}

/** Subscribe a component to live messages of the given types. */
export function useStream(handler: Listener, active = true) {
  const { onStream } = useApp();
  const ref = useRef(handler); ref.current = handler;
  useEffect(() => (active ? onStream((m) => ref.current(m)) : undefined), [onStream, active]);
}

export function AppProvider({ api, initialStatus, children }: { api: AgentGuardApi; initialStatus: Status; children: ReactNode }) {
  const [status, setStatus] = useState<Status | null>(initialStatus);
  const [conn, setConn] = useState<ConnectionState>('connecting');
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [pending, setPending] = useState<Approval[]>([]);
  const listeners = useRef(new Set<Listener>());
  const toastId = useRef(1);

  const toast = useCallback((text: string, kind: Toast['kind'] = 'info') => {
    const id = toastId.current++;
    setToasts((t) => [...t.slice(-3), { id, kind, text }]);
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === 'error' ? 7000 : 4000);
  }, []);
  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const refreshPending = useCallback(() => {
    api.approvals('pending').then(setPending).catch(() => undefined);
  }, [api]);

  useEffect(() => {
    refreshPending();
    return api.subscribe((m) => {
      if (m.type === 'hello' || m.type === 'status') setStatus(m.data);
      if (m.type === 'approval') {
        const a = m.data;
        setPending((list) => {
          const rest = list.filter((x) => x.id !== a.id);
          return a.status === 'pending' ? [a, ...rest] : rest;
        });
      }
      if (m.type === 'hello') refreshPending();
      for (const l of listeners.current) l(m);
    }, setConn);
  }, [api, refreshPending]);

  const onStream = useCallback((l: Listener) => {
    listeners.current.add(l);
    return () => { listeners.current.delete(l); };
  }, []);

  const value = useMemo<AppCtx>(() => ({ api, status, setStatus, conn, onStream, toasts, toast, dismissToast, pending, refreshPending }),
    [api, status, conn, onStream, toasts, toast, dismissToast, pending, refreshPending]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
