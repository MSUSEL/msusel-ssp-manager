import React from 'react';
import './ControlDetails.css';

interface ControlDetailsProps {
  guidance: string;
  statements: string[];
}

const ControlDetails: React.FC<ControlDetailsProps> = ({ guidance, statements }) => {
  return (
    <div className="control-details">
      <p>{guidance}</p>
      <ul>
        {statements.map((statement, index) => (
          <li key={index}>{statement}</li>
        ))}
      </ul>
    </div>
  );
};

export default ControlDetails;