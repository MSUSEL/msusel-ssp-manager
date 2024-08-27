import React from 'react';
import { Box, Heading } from '@radix-ui/themes';
import FileUploader from './FileUploader'; // Adjust the import path as necessary

const Validate: React.FC = () => {
  return (
    <Box as="div" className="main-content">
      <Heading>Validate OSCAL Document</Heading>
      <p>This is the validate OSCAL documents page.</p>
      <FileUploader apiEndpoint="/api/validate/shared"/>
    </Box>
  );
};

export default Validate;
