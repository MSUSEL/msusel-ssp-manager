import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { Box, Heading, Flex } from '@radix-ui/themes';
import Header from './Header';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import Home from './Home';
import GenerateTemplate from './GenerateTemplate';
import './MainContent.css';

// MainContent component (includes Router, Navbar, and Routes)
const MainContent: React.FC = () => {
  return (
    <Router>
      <Header />
      <Navbar />
      <Flex className="content-container">
        <Sidebar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/generate-template" element={<GenerateTemplate />} />
        </Routes>
      </Flex>
    </Router>
  );
};

export default MainContent;
