import { useCallback, useEffect, useState } from 'react';

export type ThemePref = 'system' | 'light' | 'dark';
const KEY = 'agentguard.theme';

function read(): ThemePref {
  try { const v = window.localStorage.getItem(KEY); if (v === 'light' || v === 'dark') return v; } catch { /* ignore */ }
  return 'system';
}

function systemDark() { return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false; }

export function applyTheme(pref: ThemePref) {
  const root = document.documentElement;
  if (pref === 'system') delete root.dataset.theme; else root.dataset.theme = pref;
}

export function useTheme() {
  const [pref, setPref] = useState<ThemePref>(read);
  const [sysDark, setSysDark] = useState(systemDark);
  useEffect(() => {
    const mq = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!mq) return;
    const on = () => setSysDark(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  useEffect(() => { applyTheme(pref); }, [pref]);
  const resolved: 'light' | 'dark' = pref === 'system' ? (sysDark ? 'dark' : 'light') : pref;
  const toggle = useCallback(() => {
    const next: ThemePref = resolved === 'dark' ? 'light' : 'dark';
    // Returning to the OS setting keeps following it; otherwise remember the explicit choice.
    const store: ThemePref = (next === 'dark') === systemDark() ? 'system' : next;
    try { if (store === 'system') window.localStorage.removeItem(KEY); else window.localStorage.setItem(KEY, store); } catch { /* ignore */ }
    setPref(store);
  }, [resolved]);
  return { resolved, toggle };
}

// Apply as early as possible to avoid a flash on load.
applyTheme(read());
