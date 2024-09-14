import React, { useState } from 'react';
import './SecurityControls.css';
import controls from '/app/public/example.json';

interface Control {
  id: string;
  title: string;
  statements: string[];
  guidance: string;
}

//const controls: Control[] = require('/app/public/example.json');

const SecurityControls: React.FC = () => {
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);

  const handleToggleDetails = (id: string) => {
    setExpandedControlId(expandedControlId === id ? null : id);
  };

  return (
    <div className="controls-container">
      {controls.map((control) => (
        <div key={control.id} className="control-card">
          <h3>{control.title}</h3>
          <button className="toggle-button" onClick={() => handleToggleDetails(control.id)}>
            {expandedControlId === control.id ? 'Hide Details' : 'Show Details'}
          </button>
          {expandedControlId === control.id && (
            <div className="control-details">
              <h4>Statements:</h4>
              <ul>
                {control.statements.map((statement, index) => (
                  <li key={index}>{statement}</li>
                ))}
              </ul>
              <h4>Guidance:</h4>
              <p>{control.guidance}</p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default SecurityControls;
