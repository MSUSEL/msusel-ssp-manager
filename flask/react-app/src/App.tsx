import React from 'react';
import { Flex } from '@radix-ui/themes';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MainContent from './components/MainContent';

const App: React.FC = () => {
  return (
    <Flex direction="column" height="100vh">
      <Header />
      <Flex direction="row" style={{ flex: 1 }}>
        <Sidebar />
        <MainContent />
      </Flex>
    </Flex>
  );
};

export default App;
