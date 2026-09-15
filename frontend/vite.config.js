import { fileURLToPath, URL } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/_bot_gate/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        admin: fileURLToPath(new URL('./admin.html', import.meta.url)),
        challenge: fileURLToPath(new URL('./challenge.html', import.meta.url)),
      },
    },
  },
});
