import React from 'react';
import '../styles/Field.css';

const Field = ({ fieldName, value }) => {
  return (
    <div className="field">
      <strong>{fieldName}: </strong>
      <span>{value}</span>
    </div>
  );
};

export default Field;