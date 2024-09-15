import React from 'react';
import { useNavigate } from 'react-router-dom';
import './SecurityControls.css';
import controls from '/app/public/example.json'; // Adjust the path as needed
import ControlCard from './ControlCard';

interface Control {
  id: string;
  title: string;
  statements: string[];
  guidance: string;
}

const SecurityControls: React.FC = () => {
  const navigate = useNavigate();

  const handleToggleDetails = (control: Control) => {
    navigate('/control-details', { state: { guidance: control.guidance, statements: control.statements } });
  };

  return (
    <div className="controls-container">
      {controls.map((control: Control) => (
        <ControlCard
          key={control.id}
          control={control}
          onToggleDetails={() => handleToggleDetails(control)}
        />
      ))}
    </div>
  );
};

export default SecurityControls;