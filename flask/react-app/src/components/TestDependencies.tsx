import React from 'react';
import { Box, Heading } from '@radix-ui/themes';
import TestDepnRequest from './TestDepnRequest';
import './TestDependencies.css';

const TestDependencies: React.FC = () => {
  return (
    <Box as="div" className="main-content">
      <Heading className="dependencies-heading"></Heading>
      <div className="dependencies-intro">
        <p></p>
      </div>
      <TestDepnRequest apiEndpoint="/api/test/dependencies"/>
    </Box>
  );
};

export default TestDependencies;
