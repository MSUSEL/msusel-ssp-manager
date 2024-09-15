import React from 'react';
import ControlDetails from './ControlDetails';

interface Control {
  id: string;
  title: string;
  statements: string[];
  guidance: string;
}

interface ControlCardProps {
  control: Control;
  onToggleDetails: () => void;
}

const ControlCard: React.FC<ControlCardProps> = React.memo(({ control, onToggleDetails }) => {
  return (
    <div className="control-card">
      <div className="content">
        <h3>{control.id} {control.title}</h3>
      </div>
      <button className="toggle-button" onClick={onToggleDetails}>
        Show Details
      </button>
    </div>
  );
});

export default ControlCard;