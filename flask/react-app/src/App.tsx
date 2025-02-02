import React from 'react';
import { Theme } from '@radix-ui/themes';
import '@radix-ui/themes/styles.css';
import { Flex } from '@radix-ui/themes';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MainContent from './components/MainContent';
import { BrowserRouter as Router } from 'react-router-dom';

const App: React.FC = () => {
  return (
    <Router>
      <Theme>
        <Flex direction="column" height="100vh">
          <Header />
          <Flex direction="row" style={{ flex: 1 }}>
            <Sidebar />
            <MainContent />
          </Flex>
        </Flex>
      </Theme>
    </Router>
  );
};

export default App;
