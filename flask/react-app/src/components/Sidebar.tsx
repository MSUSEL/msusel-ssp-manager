import React from 'react';
import { Box } from '@radix-ui/themes';
import { Link } from 'react-router-dom';
import './Sidebar.css';

const Sidebar: React.FC = () => {
  return (
    <Box as="nav" className="sidebar">
      <h2>OSCAL</h2>
      <ul>
        <li><Link to="/generate-template">Generate Template</Link></li>
        <li><Link to="/edit">Edit</Link></li>
        <li><Link to="/validate">Validate</Link></li>
        <li><Link to="/convert">Convert</Link></li>
        <li><Link to="/current-status">Current Status</Link></li>
      </ul>
      <h2>Vulnerability Effectiveness</h2>
      <ul>
        <li><Link to="/test-dependencies">Test Dependencies</Link></li>
        <li><Link to="/attack-techniques">Attack Techniques</Link></li>
        <li><Link to="/attack-paths">Attack Paths</Link></li>
        <li><Link to="/priority-controls">Priority Controls</Link></li>
        <li><Link to="/vulnerable-functions">Vulnerable Functions</Link></li>
      </ul>
      <ul>
      <h2>Security Data Collections</h2>
        <li><Link to="/bron-database">BRON Database</Link></li>
      </ul>
      <h2>Documentation</h2>
      <ul>
        <li><Link to="/oscal-documentation">Tool Documentation</Link></li>
      </ul>
      <h2>External Links</h2>
      <ul>
        <li><Link to="/oscal-documentation">OSCAL Documentation</Link></li>
      </ul>
    </Box>
  );
};

export default Sidebar;
