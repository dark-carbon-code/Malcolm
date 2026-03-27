import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // Proxy /api calls to the Malcolm LLM gateway container.
      // In Docker Compose, the gateway runs as 'malcolm-llm-gateway:8000'.
      // In local dev, default to localhost:8000.
      '/api': {
        target: process.env.VITE_GATEWAY_URL || 'http://localhost:8000',
        changeOrigin: true,
        rewrite: function (path) {
          return path.replace(/^\/api/, '');
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
