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
  CWE_ID?: string | string[];  // Updated to handle both string and array
}

const ControlMappings: React.FC = () => {
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    // Log the first mapping to see its structure
    if (Array.isArray(mappings) && mappings.length > 0) {
      console.log('Sample mapping:', mappings[0]);
    }
    setIsLoading(false);
  }, []);

  const getCWEs = (mapping: Mapping) => {
    if (!mapping.Technique_ID) return [];
    
    const techniqueIds = mapping.Technique_ID.split(',').map(t => t.trim());
    const cwes = new Set<string>();
    
    techniqueIds.forEach(techniqueId => {
      // Find matching techniques including sub-techniques
      const matchingTechniques = techniqueCWEs.filter(tc => {
        const techId = tc.tech.replace('technique/', '');
        return techId.startsWith(techniqueId);
      });
      
      // Add all CWEs from matching techniques
      matchingTechniques.forEach(technique => {
        technique.cwe.forEach((cwe: string) => cwes.add(cwe));
      });
    });
    
    return Array.from(cwes);
  };

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
              {filteredMappings.map((mapping: Mapping, index) => {
                const cwes = getCWEs(mapping);
                return (
                  <tr key={index}>
                    <td>{mapping.Control_ID}</td>
                    <td>{mapping.Control_Name}</td>
                    <td>
                      {mapping.Technique_ID ? (
                        <ul>
                          {mapping.Technique_ID.split(',').map((technique, i) => (
                            <li key={i}>
                              <a 
                                href={`https://attack.mitre.org/techniques/${technique.trim()}`} 
                                target="_blank" 
                                rel="noopener noreferrer"
                              >
                                {technique.trim()}
                              </a>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        'N/A'
                      )}
                    </td>
                    <td>
                      {cwes.length > 0 ? (
                        <ul>
                          {cwes.map((cwe, i) => (
                            <li key={i}>
                              <a 
                                href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`} 
                                target="_blank" 
                                rel="noopener noreferrer"
                              >
                                {cwe}
                              </a>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        'N/A'
                      )}
                    </td>
                  </tr>
                );
              })}
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
