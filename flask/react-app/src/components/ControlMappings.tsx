import React, { useState, useEffect } from 'react';
import { Box } from '@radix-ui/themes';
import mappings from '../data/mappings.json';
import techniqueCWEs from '../data/technique-cwes.json';
import cweCollection from '../data/cwe_collection.json';
import controls from '../data/NIST_SP-800-53_rev5_catalog.json';
import techniques from '../data/techniques.json';
import './ControlMappings.css';

interface Mapping {
  Control_ID: string;
  Control_Name: string;
  Technique_ID?: string;
  CWE_ID?: string;
}

const ControlMappings: React.FC = () => {
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    setIsLoading(false);
  }, []);

  const filteredMappings = Array.isArray(mappings) 
    ? mappings.filter((mapping: Mapping) => 
        mapping.Control_ID.toLowerCase().includes(searchTerm.toLowerCase()) ||
        mapping.Control_Name.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : [];

  if (isLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="mappings-container">
      <h1>Control Mappings</h1>
      
      <div className="search-container">
        <input
          type="text"
          placeholder="Search controls..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-input"
        />
      </div>

      <div className="table-container">
        {filteredMappings.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Control ID</th>
                <th>Control Name</th>
                <th>Associated Techniques</th>
                <th>Related CWEs</th>
              </tr>
            </thead>
            <tbody>
              {filteredMappings.map((mapping: Mapping, index) => (
                <tr key={index}>
                  <td>{mapping.Control_ID}</td>
                  <td>{mapping.Control_Name}</td>
                  <td>
                    {mapping.Technique_ID ? (
                      <ul>
                        {mapping.Technique_ID.split(',').map((technique, i) => (
                          <li key={i}>{technique.trim()}</li>
                        ))}
                      </ul>
                    ) : (
                      'N/A'
                    )}
                  </td>
                  <td>
                    {mapping.CWE_ID ? (
                      <ul>
                        {mapping.CWE_ID.split(',').map((cwe, i) => (
                          <li key={i}>{cwe.trim()}</li>
                        ))}
                      </ul>
                    ) : (
                      'N/A'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No mappings found</p>
        )}
      </div>
    </div>
  );
};

export default ControlMappings;
