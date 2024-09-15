import React from 'react';
import { useLocation } from 'react-router-dom';
import ControlDetails from './ControlDetails';

interface ControlDetailsWrapperProps {
  guidance: string;
  statements: string[];
}

const ControlDetailsWrapper: React.FC = () => {
  const location = useLocation();
  const { guidance, statements } = location.state as ControlDetailsWrapperProps;

  return <ControlDetails guidance={guidance} statements={statements} />;
};

export default ControlDetailsWrapper;