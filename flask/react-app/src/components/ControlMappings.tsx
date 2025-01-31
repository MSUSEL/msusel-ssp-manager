import React, { useState } from 'react';
import './ControlMappings.css';
import mappings from '/app/public/mappings.json';

interface Mapping {
  Control_ID: string;
  Control_Name: string;
  Mapping_Type: string;
  Technique_ID: string;
  Technique_Name: string;
}

const ControlMappings: React.FC = () => {
  const [filter, setFilter] = useState('');
  const [filterType, setFilterType] = useState<'control' | 'technique'>('control');

  const filteredMappings = mappings.filter((mapping: Mapping) => {
    const searchTerm = filter.toLowerCase();
    if (filterType === 'control') {
      return mapping.Control_ID.toLowerCase().includes(searchTerm) ||
             mapping.Control_Name.toLowerCase().includes(searchTerm);
    } else {
      return mapping.Technique_ID.toLowerCase().includes(searchTerm) ||
             mapping.Technique_Name.toLowerCase().includes(searchTerm);
    }
  });

  return (
    <div className="mappings-container">
      <div className="mappings-header">
        <h1>NIST SP 800-53 to MITRE ATT&CK Mappings</h1>
        <div className="filter-controls">
          <input
            type="text"
            placeholder="Filter mappings..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="filter-input"
          />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as 'control' | 'technique')}
            className="filter-select"
          >
            <option value="control">Filter by Control</option>
            <option value="technique">Filter by Technique</option>
          </select>
        </div>
      </div>
      
      <div className="mappings-grid">
        {filteredMappings.map((mapping: Mapping, index: number) => (
          <div key={index} className="mapping-card">
            <div className="control-section">
              <h3>{mapping.Control_ID}</h3>
              <p>{mapping.Control_Name}</p>
            </div>
            <div className="mapping-arrow">
              <span>{mapping.Mapping_Type}</span>
              <span>→</span>
            </div>
            <div className="technique-section">
              <h3>{mapping.Technique_ID}</h3>
              <p>{mapping.Technique_Name}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ControlMappings;
