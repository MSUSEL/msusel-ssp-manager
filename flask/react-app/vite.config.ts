import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',  // Bind to all network interfaces
    port: 3000,       // Ensure port 3000 is used
    proxy: {
      '/api': {
        target: 'http://flask:5000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
