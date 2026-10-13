/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

const src = fileURLToPath(new URL('./src', import.meta.url));
const backend = fileURLToPath(new URL('../backend/src', import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': src, '@backend': backend } },
  build: {
    target: 'es2020',
    sourcemap: false, // no source maps in production: they expose the code and add nothing for users
    chunkSizeWarningLimit: 300,
    rollupOptions: { output: { manualChunks: { react: ['react', 'react-dom', 'react-router-dom'], query: ['@tanstack/react-query'] } } },
  },
  server: { port: 5173, host: '127.0.0.1' },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/test/**', 'src/**/*.test.*', 'src/main.tsx', 'src/lib/route-matrix.json'],
      reporter: ['text-summary', 'text'],
      thresholds: { statements: 95, lines: 95, functions: 88, branches: 82 },
    },
  },
});
