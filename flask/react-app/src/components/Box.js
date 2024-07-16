import React, { useState } from 'react';
import Field from './Field';
import ToggleButton from './ToggleButton';
import '../styles/Box.css';

const Box = ({ data }) => {
  const [showDetails, setShowDetails] = useState(false);

  const handleToggle = () => {
    setShowDetails(!showDetails);
  };

  return (
    <div className="box">
      <Field fieldName="ID" value={data.id} />
      <Field fieldName="Title" value={data.title} />
      <ToggleButton onClick={handleToggle} showDetails={showDetails} />
      {showDetails && (
        <div>
          <Field fieldName="Statements" value={data.statements.join(' ')} />
          <Field fieldName="Guidance" value={data.guidance} />
        </div>
      )}
    </div>
  );
};

export default Box;

