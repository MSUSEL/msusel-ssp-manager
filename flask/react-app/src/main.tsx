import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css'; // Ensure your existing global CSS is also imported
import '@radix-ui/themes/styles.css'; // Import the Radix UI global CSS
import { Theme } from '@radix-ui/themes'; // Import the Theme component

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <Theme>
      <App />
    </Theme>
  </React.StrictMode>,
);
