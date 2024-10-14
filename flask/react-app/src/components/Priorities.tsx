import React, { useState, useEffect } from 'react';
import './Priorities.css'; // CSS file for custom styles

interface TechniquesData {
  [key: string]: Record<string, any>;
}

const Priorities: React.FC = () => {
  const [data, setData] = useState<TechniquesData | null>(null);
  const [headers, setHeaders] = useState<string[]>([]);

  useEffect(() => {
    fetch('/api/priority/table_data') // Replace with your actual API endpoint
      .then(response => response.json())
      .then(fetchedData => {
        setData(fetchedData);

        const dynamicHeaders = new Set<string>();
        Object.values(fetchedData).forEach((entry: any) => {
          Object.keys(entry).forEach((key) => dynamicHeaders.add(key));
        });

        setHeaders(Array.from(dynamicHeaders));
      })
      .catch(error => console.error('Error fetching data:', error));
  }, []);

  if (!data || headers.length === 0) {
    return <div>Loading...</div>;
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Tactic</th>
          {headers.map((header) => (
            <th key={header}>{header}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {Object.entries(data).map(([tactic, tacticData]) => (
          <tr key={tactic} className="tactic-row">
            <td>{tactic}</td>
            {headers.map((header) => (
              <td key={header}>
                {Array.isArray(tacticData[header]) ? (
                  <ul>
                    {tacticData[header].map((item: string, index: number) => (
                      <li key={index}>{item}</li>
                    ))}
                  </ul>
                ) : (
                  tacticData[header] || 'N/A'
                )}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
};

export default Priorities;
