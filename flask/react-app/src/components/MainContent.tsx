import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { Box, Heading, Flex } from '@radix-ui/themes';
import Header from './Header';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import Home from './Home';
import GenerateTemplate from './GenerateTemplate';
import Validate from './Validate';
import TestDependencies from './TestDependencies';
import AttackTechniques from './AttackTechniques';
import AttackPaths from './AttackPaths';
import PriorityControls from './PriorityControls';
import VulnerableFunctions from './VulnerableFunctions';
import SecurityControls from './SecurityControls';
import './MainContent.css';
import ControlDetailsWrapper from './ControlDetailsWrapper';
import Priorities from './Priorities';
import PriorityStage from './PriorityStage';
import IssueDetails from './IssueDetails';

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
          <Route path="/validate" element={<Validate />} />
          <Route path="/test-dependencies" element={<TestDependencies />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/security-controls" element={<SecurityControls />} />
          <Route path="/control-details" element={<ControlDetailsWrapper />} />
          <Route path="/priorities" element={<Priorities />} />
          <Route path="/priority-stage" element={<PriorityStage />} />
          <Route path="/vulnerable-functions" element={<VulnerableFunctions />} />
          <Route path="/issue-details" element={<IssueDetails />} />
        </Routes>
      </Flex>
    </Router>
  );
};

export default MainContent;
