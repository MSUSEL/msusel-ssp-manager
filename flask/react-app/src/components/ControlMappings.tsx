import React, { useState, useEffect, useMemo } from 'react';
import { Dialog } from '@radix-ui/themes';
import mappings from '../data/mappings.json';
import techniqueCWEs from '../data/technique-cwes.json';
import cweCollection from '../data/cwe_collection.json';
import techniques from '../data/techniques.json';
import './ControlMappings.css';

interface Mapping {
  Control_ID: string;
  Control_Name: string;
  Technique_ID?: string;
  CWE_ID?: string | string[];
}

interface CWE {
  _key: string;
  _id?: string;
  _rev?: string;
  original_id?: string;
  datatype?: string;
  name: string;
  metadata: {
    short_description: string;
    description: string;
    likeliehood_of_exploit: string;
    common_consequences: Array<{
      Impact: string;
      Note: string;
      Scope: string;
    }>;
    applicable_platform: string[];
  };
}

interface Technique {
  _key: string;
  name: string;
  metadata: {
    description: string;
    short_description: string;
  };
}

const formatTechniqueUrl = (techniqueId: string): string => {
  return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}`;
};

const getTechniqueDetails = (techniqueId: string): Technique | undefined => {
  // Remove any 'technique/' prefix if present
  const techKey = techniqueId.replace('technique/', '');
  
  // Search through all values to find matching _key
  const technique = Object.values(techniques).find(
    (entry: Technique) => entry._key === techKey
  );
  
  return technique;
};

interface CWEModalProps {
  cwe: CWE;
  onClose: () => void;
}

const CWEModal: React.FC<CWEModalProps> = ({ cwe, onClose }) => (
  <Dialog.Root open onOpenChange={onClose}>
    <Dialog.Content style={{ maxWidth: 600 }}>
      <Dialog.Title>{cwe._key}: {cwe.name}</Dialog.Title>
      <Dialog.Description size="2">
        <h4>Description</h4>
        <p>{cwe.metadata.description}</p>
        
        <h4>Likelihood of Exploit</h4>
        <p>{cwe.metadata.likeliehood_of_exploit}</p>
        
        <h4>Common Consequences</h4>
        {cwe.metadata.common_consequences.map((consequence, index) => (
          <div key={index} style={{ marginBottom: '10px' }}>
            <strong>Scope:</strong> {consequence.Scope}<br />
            <strong>Impact:</strong> {consequence.Impact}<br />
            <strong>Note:</strong> {consequence.Note}
          </div>
        ))}
        
        <h4>Applicable Platforms</h4>
        <ul>
          {cwe.metadata.applicable_platform.map((platform, index) => (
            <li key={index}>{platform}</li>
          ))}
        </ul>
      </Dialog.Description>
      <Dialog.Close />
    </Dialog.Content>
  </Dialog.Root>
);

const ControlCard: React.FC<{
  mapping: Mapping;
}> = ({ mapping }) => {
  const [selectedCWE, setSelectedCWE] = useState<CWE | null>(null);

  const getCWEs = () => {
    if (!mapping.Technique_ID) return [];
    
    const techniqueIds = mapping.Technique_ID.split(',').map(t => t.trim());
    const cwes = new Set<string>();
    
    techniqueIds.forEach(techniqueId => {
      // Remove any 'technique/' prefix for matching
      const techId = techniqueId.replace('technique/', '');
      
      const matchingTechniques = techniqueCWEs.filter(tc => {
        const tcTechId = tc.tech.replace('technique/', '');
        return tcTechId === techId;
      });
      
      matchingTechniques.forEach(technique => {
        technique.cwe.forEach((cwe: string) => cwes.add(cwe));
      });
    });
    
    return Array.from(cwes);
  };

  const getCWEDetails = (cweId: string): CWE | undefined => {
    // Remove any existing CWE- prefix and get just the number
    const numberOnly = cweId.replace('CWE-', '');
    const searchKey = `CWE-${numberOnly}`;
    
    // Search through all values to find matching _key
    const cwe = Object.values(cweCollection).find(
      (entry: CWE) => entry._key === searchKey
    );
    
    return cwe;
  };

  const formatCWEUrl = (cweId: string): string => {
    return `https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`;
  };

  const cweList = getCWEs();

  return (
    <div className="control-card">
      <div className="control-header">
        <h3>{mapping.Control_ID}</h3>
        <h4>{mapping.Control_Name}</h4>
      </div>
      
      <div className="techniques-section">
        <h5>Associated Techniques</h5>
        {mapping.Technique_ID ? (
          <ul>
            {mapping.Technique_ID.split(',').map((technique, i) => (
              <li key={i}>
                <a 
                  href={formatTechniqueUrl(technique.trim())}
                  target="_blank" 
                  rel="noopener noreferrer"
                >
                  {(() => {
                    const techDetails = getTechniqueDetails(technique);
                    const techId = technique.replace('technique/', '');
                    return techDetails 
                      ? `${techId}: ${techDetails.name}`
                      : techId;
                  })()}
                </a>
              </li>
            ))}
          </ul>
        ) : (
          <p>No associated techniques</p>
        )}
      </div>

      <div className="cwes-section">
        <h5>Related CWEs</h5>
        {cweList.length > 0 ? (
          <ul>
            {cweList.map((cweId, i) => {
              const cwe = getCWEDetails(cweId);
              return (
                <li key={i}>
                  <a 
                    className="cwe-link"
                    href={formatCWEUrl(cwe?._key || cweId)}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={cwe?.metadata.short_description}
                  >
                    {cweId}: {cwe?.name || 'Unknown'}
                  </a>
                </li>
              );
            })}
          </ul>
        ) : (
          <p>No related CWEs</p>
        )}
      </div>

      {selectedCWE && (
        <CWEModal 
          cwe={selectedCWE} 
          onClose={() => setSelectedCWE(null)} 
        />
      )}
    </div>
  );
};

const ControlMappings: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortConfig, setSortConfig] = useState({
    field: 'Control_ID' as const,
    direction: 'asc' as const
  });

  // Validate mappings data on component mount
  useEffect(() => {
    if (!Array.isArray(mappings)) {
      console.error('Expected mappings to be an array');
    }
  }, []);

  const handleSort = (field: 'Control_ID' | 'Control_Name' | 'Technique_ID') => {
    setSortConfig(prevConfig => ({
      field,
      direction: prevConfig.field === field && prevConfig.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  const filteredAndSortedMappings = useMemo(() => {
    if (!Array.isArray(mappings)) return [];

    return [...mappings]
      .filter((mapping: Mapping) => {
        const searchLower = searchTerm.toLowerCase();
        return (
          mapping.Control_ID.toLowerCase().includes(searchLower) ||
          mapping.Control_Name.toLowerCase().includes(searchLower) ||
          (mapping.Technique_ID || '').toLowerCase().includes(searchLower)
        );
      })
      .sort((a: Mapping, b: Mapping) => {
        const aValue = a[sortConfig.field] || '';
        const bValue = b[sortConfig.field] || '';
        
        if (sortConfig.direction === 'asc') {
          return aValue.localeCompare(bValue);
        } else {
          return bValue.localeCompare(aValue);
        }
      });
  }, [mappings, searchTerm, sortConfig]);

  return (
    <div className="mappings-container">
      <div className="controls-section">
        <div className="search-controls">
          <input
            type="text"
            placeholder="Search controls..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        
        <div className="sort-controls">
          <button onClick={() => handleSort('Control_ID')}>
            Sort by ID {sortConfig.field === 'Control_ID' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
          </button>
          <button onClick={() => handleSort('Control_Name')}>
            Sort by Name {sortConfig.field === 'Control_Name' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
          </button>
          <button onClick={() => handleSort('Technique_ID')}>
            Sort by Technique {sortConfig.field === 'Technique_ID' && (sortConfig.direction === 'asc' ? '↑' : '↓')}
          </button>
        </div>
      </div>

      <div className="cards-container">
        {filteredAndSortedMappings.length > 0 ? (
          filteredAndSortedMappings.map((mapping, index) => (
            <ControlCard 
              key={`${mapping.Control_ID}-${index}`}
              mapping={mapping}
            />
          ))
        ) : (
          <p>No mappings found</p>
        )}
      </div>
    </div>
  );
};

export default ControlMappings;
