import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': {
        target: process.env.REACT_APP_API_URL || 'http://10.224.0.1',  // Replace with your Flask service internal IP
        changeOrigin: true,
        secure: false
      },
    },
  },
});
