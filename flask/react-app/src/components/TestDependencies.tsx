import React from 'react';
import { Box, Heading } from '@radix-ui/themes';
import TestDepnRequest from './TestDepnRequest';

const GenerateTemplate: React.FC = () => {
  return (
    <Box as="div" className="main-content">
      <Heading>Test Dependencies</Heading>
      <p>Find reachable vulnerabilities in your project.</p>
      <p>Temporarily disabled for testing visualizations without having to run the tests.</p>
      <TestDepnRequest apiEndpoint="/api/test/dependencies"/>
    </Box>
  );
};
//????
export default GenerateTemplate;
