import React from 'react';
import { Box } from '@radix-ui/themes';
import './Sidebar.css';

const Sidebar: React.FC = () => {
  return (
    <Box as="nav" className="sidebar">
      <h2>OSCAL</h2>
      <ul>
        <li>Generate Template</li>
        <li>Edit</li>
        <li>Validate</li>
        <li>Convert</li>
        <li>Current Status</li>
      </ul>
      <h2>Vulnerability Effectiveness</h2>
      <ul>
        <li>Test Dependencies</li>
        <li>Attack Techniques</li>
        <li>Attack Paths</li>
        <li>Priority Controls</li>
        <li>Vulnerable Functions</li>
      </ul>
      <h2>BRON Database</h2>
      <ul>
        <li>External Links:</li>
        <li>OSCAL Documentation</li>
        <li>Tool Documentation</li>
      </ul>
    </Box>
  );
};

export default Sidebar;
