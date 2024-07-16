import React from 'react';
import '../styles/ToggleButton.css';

const ToggleButton = ({ onClick, showDetails }) => {
  return (
    <button className="toggle-button" onClick={onClick}>
      {showDetails ? 'Hide Details' : 'Show Details'}
    </button>
  );
};

export default ToggleButton;

