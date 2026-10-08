import { useCallback, useEffect, useRef, useState } from 'react';
import { errMsg } from './format';

export interface AsyncState<T> { data: T | undefined; error: string | null; loading: boolean; reload: () => void; setData: (fn: (d: T | undefined) => T | undefined) => void }

/** Loads data with a function; re-runs when deps change. Keeps stale data while reloading. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setDataState] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const fnRef = useRef(fn); fnRef.current = fn;
  useEffect(() => {
    let alive = true;
    setLoading(true);
    fnRef.current().then((d) => { if (alive) { setDataState(d); setError(null); } })
      .catch((e: unknown) => { if (alive) setError(errMsg(e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const setData = useCallback((f: (d: T | undefined) => T | undefined) => setDataState(f), []);
  return { data, error, loading, reload, setData };
}

/** Re-renders every `ms` milliseconds; returns Date.now(). */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => { const t = window.setInterval(() => setNow(Date.now()), ms); return () => window.clearInterval(t); }, [ms]);
  return now;
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => { const t = window.setTimeout(() => setV(value), ms); return () => window.clearTimeout(t); }, [value, ms]);
  return v;
}
