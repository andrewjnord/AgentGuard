import { useEffect, useState } from 'react';

export type Page = 'overview' | 'agents' | 'mcp' | 'timeline' | 'approvals' | 'alerts' | 'policy' | 'settings';
export const PAGES: Page[] = ['overview', 'agents', 'mcp', 'timeline', 'approvals', 'alerts', 'policy', 'settings'];

export interface Route { page: Page; params: URLSearchParams }

function parse(): Route {
  const h = window.location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = h.split('?');
  const page = (PAGES as string[]).includes(path) ? (path as Page) : 'overview';
  return { page, params: new URLSearchParams(query) };
}

export function href(page: Page, params?: Record<string, string | undefined>): string {
  const sp = new URLSearchParams();
  if (params) for (const [k, v] of Object.entries(params)) if (v) sp.set(k, v);
  const q = sp.toString();
  return `#/${page}${q ? `?${q}` : ''}`;
}

export function navigate(page: Page, params?: Record<string, string | undefined>) {
  window.location.hash = href(page, params);
}

export function useRoute(): Route {
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const on = () => setRoute(parse());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return route;
}
