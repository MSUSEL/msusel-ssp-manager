import React from 'react';
import { Box, Heading } from '@radix-ui/themes';
import FileUploader from './FileUploader'; // Adjust the import path as necessary

const Validate: React.FC = () => {
  return (
    <Box as="div" className="main-content">
      <Heading>Process OSCAL Document</Heading>
      <p>Select the type of OSCAL document and the desired operation.</p>
      <FileUploader apiEndpoint="/api/validate/shared"/>
    </Box>
  );
};

export default Validate;
