import React, { useState, useEffect } from 'react';
import './ControlMappings.css';
import mappings from '/app/public/mappings.json';
import techniqueCWEs from '/app/public/technique-cwes.json';
import cweCollection from '/app/public/cwe_collection.json';

interface TechniqueCWE {
  tech: string;
  cwe: string[];
}

interface CWEMetadata {
  applicable_platform: string[];
  common_consequences: Array<{
    Impact: string;
    Scope: string;
  }>;
  description: string;
  likeliehood_of_exploit: string;
  short_description: string;
}

interface CWE {
  _key: string;
  _id: string;
  original_id: string;
  name: string;
  metadata: CWEMetadata;
}

interface Mapping {
  Control_ID: string;
  Control_Name: string;
  Mapping_Type: string;
  Technique_ID: string;
  Technique_Name: string;
  relatedCWEs?: CWE[];
}

const ControlMappings: React.FC = () => {
  const [enrichedMappings, setEnrichedMappings] = useState<Mapping[]>([]);

  useEffect(() => {
    // Create a map of CWEs for faster lookup
    const cweMap = new Map(
      cweCollection.map((cwe: CWE) => [cwe.original_id, cwe])
    );

    // Enrich mappings with CWE data
    const enriched = mappings.map((mapping: Mapping) => {
      // Find technique-CWE relationships
      const techniqueId = mapping.Technique_ID.replace('.', '/');
      const cweMappings = techniqueCWEs.find(
        (t: TechniqueCWE) => t.tech === `technique/${techniqueId}`
      );
      
      // If CWE mappings exist, look up the full CWE details
      const relatedCWEs = cweMappings?.cwe
        .map(cweId => cweMap.get(cweId))
        .filter((cwe): cwe is CWE => cwe !== undefined);

      return {
        ...mapping,
        relatedCWEs: relatedCWEs || []
      };
    });

    setEnrichedMappings(enriched);
  }, []);

  const [filter, setFilter] = useState('');
  const [filterType, setFilterType] = useState<'control' | 'technique' | 'cwe'>('control');

  const filteredMappings = enrichedMappings.filter((mapping: Mapping) => {
    const searchTerm = filter.toLowerCase();
    
    switch (filterType) {
      case 'control':
        return mapping.Control_ID.toLowerCase().includes(searchTerm) ||
               mapping.Control_Name.toLowerCase().includes(searchTerm);
      
      case 'technique':
        return mapping.Technique_ID.toLowerCase().includes(searchTerm) ||
               mapping.Technique_Name.toLowerCase().includes(searchTerm);
      
      case 'cwe':
        return mapping.relatedCWEs?.some(cwe => 
          cwe.original_id.toLowerCase().includes(searchTerm) ||
          cwe.name.toLowerCase().includes(searchTerm) ||
          `cwe-${cwe.original_id}`.toLowerCase().includes(searchTerm)
        ) ?? false;
      
      default:
        return false;
    }
  });

  return (
    <div className="mappings-container">
      <div className="mappings-header">
        <h1>NIST SP 800-53 to MITRE ATT&CK Mappings</h1>
        <div className="filter-controls">
          <input
            type="text"
            placeholder={`Filter by ${filterType}...`}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="filter-input"
          />
          <select
            value={filterType}
            onChange={(e) => {
              setFilterType(e.target.value as 'control' | 'technique' | 'cwe');
              setFilter(''); // Clear filter when changing type
            }}
            className="filter-select"
          >
            <option value="control">Filter by Control</option>
            <option value="technique">Filter by Technique</option>
            <option value="cwe">Filter by CWE</option>
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
              {mapping.relatedCWEs && mapping.relatedCWEs.length > 0 && (
                <div className="cwe-section">
                  <h4>Related CWEs:</h4>
                  <ul>
                    {mapping.relatedCWEs.map((cwe, idx) => (
                      <li key={idx} className={
                        filterType === 'cwe' && 
                        (cwe.original_id.toLowerCase().includes(filter.toLowerCase()) ||
                         cwe.name.toLowerCase().includes(filter.toLowerCase()) ||
                         `cwe-${cwe.original_id}`.toLowerCase().includes(filter.toLowerCase()))
                          ? 'highlighted'
                          : ''
                      }>
                        <strong>CWE-{cwe.original_id}:</strong> {cwe.name}
                        <p className="cwe-description">{cwe.metadata.short_description}</p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ControlMappings;
