import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// Mock builds (mode "mock", or VITE_MOCK=1 in the environment) go to dist-mock so they
// can never overwrite the service's wwwroot.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  const mock = mode === 'mock' || env.VITE_MOCK === '1';
  return {
    base: '/',
    plugins: [react()],
    build: {
      outDir: mock ? 'dist-mock' : '../AgentGuard.Service/wwwroot',
      emptyOutDir: true,
      sourcemap: false,
      chunkSizeWarningLimit: 600,
    },
    server: {
      port: 5173,
      proxy: {
        '/api': { target: 'http://127.0.0.1:47823', changeOrigin: false, ws: false },
      },
    },
    preview: { port: 4173 },
  };
});
