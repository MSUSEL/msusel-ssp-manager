import React, { useState } from 'react';
import './SecurityControls.css';
import controls from '/app/public/example.json'; // Adjust the path as needed

interface Control {
  id: string;
  title: string;
  statements: string[];
  guidance: string;
}

const SecurityControls: React.FC = () => {
  const [expandedControlId, setExpandedControlId] = useState<string | null>(null);

  const handleToggleDetails = (id: string) => {
    setExpandedControlId(expandedControlId === id ? null : id);
  };

  return (
    <div className="controls-container">
      {controls.map((control: Control) => (
        <div key={control.id} className="control-card">
          <div className="content">
            <h3>{control.id} {control.title}</h3>
          </div>
          <button className="toggle-button" onClick={() => handleToggleDetails(control.id)}>
            {expandedControlId === control.id ? 'Hide Details' : 'Show Details'}
          </button>
          {expandedControlId === control.id && (
            <div className="control-details">
              <p>{control.guidance}</p>
              <ul>
                {control.statements.map((statement, index) => (
                  <li key={index}>{statement}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default SecurityControls;