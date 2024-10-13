import React, { useEffect, useState } from 'react';

interface Technique {
  tech_id: string;
  tech_name: string;
  ctrl: string[];
}

const Priorities: React.FC = () => {
  const [techniques, setTechniques] = useState<Technique[]>([]);

  useEffect(() => {
    fetch('/api/priority/table_data')
      .then(response => response.json())
      .then(data => setTechniques(data))
      .catch(error => console.error('Error fetching techniques:', error));
  }, []);

  return (
    <table>
      <thead>
        <tr>
          <th>Technique ID</th>
          <th>Technique Name</th>
          <th>Controls</th>
        </tr>
      </thead>
      <tbody>
        {techniques.map((technique) => (
          <tr key={technique.tech_id}>
            <td>{technique.tech_id}</td>
            <td>{technique.tech_name}</td>
            <td>{technique.ctrl.join(', ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

export default Priorities;
