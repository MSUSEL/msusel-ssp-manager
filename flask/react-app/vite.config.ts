import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://flask:5000',
        changeOrigin: true,
        secure: false,
        timeout: 600000, // 10 minutes timeout (increased from 5 minutes)
        proxyTimeout: 600000, // 10 minutes proxy timeout (increased from 5 minutes)
        // Additional timeout configurations to handle long-running requests
        proxyReqTimeout: 600000, // 10 minutes for request timeout
        proxyResTimeout: 600000, // 10 minutes for response timeout
      },
    },
  },
});
