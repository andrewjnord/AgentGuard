import type { AgentGuardApi } from './client';
import { HttpApi } from './http';

export const IS_MOCK = import.meta.env.VITE_MOCK === '1';

/** Creates the API implementation. The mock module is only reachable when VITE_MOCK=1 at build time. */
export async function createApi(onUnauthorized: () => void): Promise<AgentGuardApi> {
  if (import.meta.env.VITE_MOCK === '1') {
    const { MockApi } = await import('./mock/mockApi');
    return new MockApi();
  }
  return new HttpApi(onUnauthorized);
}

export * from './client';
export * from './types';
