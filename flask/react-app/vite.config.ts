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
        timeout: 10800000, // 3 hours timeout
        proxyTimeout: 10800000, // 3 hours proxy timeout
        proxyReqTimeout: 10800000, // 3 hours for request timeout
        proxyResTimeout: 10800000, // 3 hours for response timeout
      },
    },
  },
});
