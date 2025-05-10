import React from 'react';
import { Box } from '@radix-ui/themes';
import { Link } from 'react-router-dom';
import './Sidebar.css';

const Sidebar: React.FC = () => {
  return (
    <Box as="nav" className="sidebar">
      <h2>Security Controls</h2>
      <ul>
        <li><Link to="/security-controls">Catalog</Link></li>
        <li><Link to="/generate-template">Generate Template</Link></li>
        <li><Link to="/validate">Process OSCAL Document</Link></li>
        <li><Link to="/current-status">Current Status</Link></li>
      </ul>
      <h2>Control Prioritization</h2>
      <ul>
        <li><Link to="/control-mappings">Control Mappings</Link></li>
        <li><Link to="/test-dependencies">Test Dependencies</Link></li>
        <li><Link to="/priority-stage">Priority Stage</Link></li>
        <li><Link to="/attack-paths">Attack Paths</Link></li>
        <li><Link to="/priorities">Prioritiy Controls</Link></li>
        <li><Link to="/vulnerable-functions">Vulnerable Functions</Link></li>
      </ul>
      <ul>
      <h2>Security Data Collections</h2>
      <li>
          {/* External link to the database interface */}
          <a href="http://localhost:8529" target="_blank" rel="noopener noreferrer">
            BRON Database
          </a>
        </li>
      </ul>
      <h2>Documentation</h2>
      <ul>
        <li><Link to="/generate-ssp-documentation">Tool Documentation</Link></li>
      </ul>
      <h2>External Links</h2>
      <ul>
        <li>
          <a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">
            MITRE ATT&CK Framework
          </a>
        </li>
        <li>
          <a href="https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist/" target="_blank" rel="noopener noreferrer">
            MITRE Mappings Explorer
          </a>
        </li>
        <li>
          <a href="https://pages.nist.gov/OSCAL/" target="_blank" rel="noopener noreferrer">
            OSCAL Documentation
          </a>
        </li>
      </ul>
    </Box>
  );
};

export default Sidebar;
