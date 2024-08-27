import React from 'react';
import { Box, Heading } from '@radix-ui/themes';
import SFileUploader from './SFileUploader';

const GenerateTemplate: React.FC = () => {
  return (
    <Box as="div" className="main-content">
      <Heading>Generate Template</Heading>
      <p>This is the Generate Template page.</p>
      <SFileUploader apiEndpoint="/api/generate/ssp"/>
    </Box>
  );
};

export default GenerateTemplate;
