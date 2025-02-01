import React from 'react';
import ReactDOM from 'react-dom';
import MainContent from './components/MainContent';
import './index.css';
import { Theme } from '@radix-ui/themes';
import '@radix-ui/themes/styles.css';

ReactDOM.render(
  <React.StrictMode>
    <Theme>
      <MainContent />
    </Theme>
  </React.StrictMode>,
  document.getElementById('root')
);
