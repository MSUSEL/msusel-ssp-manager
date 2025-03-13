import React, { useState, useEffect } from 'react';
import './Priorities.css';

interface TechniqueData {
  'Control (Name)': string[];
  'Technique ID': string;
  'Technique Name': string;
  cwe: string[];
}

interface TechniquesData {
  [key: string]: TechniqueData;
}

interface PriorityData {
  tactic: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  controls: string[];
  cwe: string[];
}

const Priorities: React.FC = () => {
  const [data, setData] = useState<PriorityData[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchPriorityData = async () => {
      try {
        const response = await fetch('/api/priority/table_data');
        if (!response.ok) {
          throw new Error('Failed to fetch priority data');
        }
        
        const fetchedData: TechniquesData = await response.json();
        console.log('Fetched data:', fetchedData);
        
        // Transform the data into our preferred format
        const transformedData: PriorityData[] = Object.entries(fetchedData).map(([tactic, data]) => ({
          tactic: tactic.split(' (')[0],
          tacticName: tactic.split(' (')[1]?.replace(')', '') || tactic,
          techniqueId: data['Technique ID'],
          techniqueName: data['Technique Name'],
          controls: data['Control (Name)'],
          cwe: data.cwe
        }));

        console.log('Transformed data:', transformedData);
        setData(transformedData);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
        console.error('Error fetching data:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchPriorityData();
  }, []);

  return (
    <div className="priorities-container">
      <h1>Security Control Priorities</h1>
      <p className="priorities-description">
        Tactics are prioritized based on ease of mitigation. 
        Tactics with fewer techniques to neutralize appear first, 
        as they may be easier to defend against.
      </p>
      
      <div className="priority-cards">
        {data.map((item, index) => (
          <div 
            key={item.tactic} 
            className={`priority-card priority-level-${Math.min(Math.floor(index / 3) + 1, 3)}`}
          >
            <div className="priority-header">
              <span className="priority-number">Priority {index + 1}</span>
              <h2>{item.tacticName}</h2>
              <span className="tactic-id">{item.tactic}</span>
            </div>

            <div className="priority-content">
              <div className="techniques-section">
                <h3>Associated Technique</h3>
                <div className="technique-info">
                  <p>{item.techniqueName} ({item.techniqueId})</p>
                  {item.cwe.length > 0 && (
                    <p className="cwe-info">Associated CWE: {item.cwe.join(', ')}</p>
                  )}
                </div>

                {item.controls && item.controls.length > 0 && (
                  <div className="controls-section">
                    <h4>Related Controls:</h4>
                    <ul>
                      {item.controls.map((control, controlIdx) => (
                        <li key={controlIdx}>{control}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Priorities;
