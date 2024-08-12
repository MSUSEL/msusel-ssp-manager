import React, { useState, useEffect } from 'react';
import { Box, Heading, Button } from '@radix-ui/themes';
import FileUploader from './FileUploader'; // Adjust the import path as necessary

const GenerateTemplate: React.FC = () => {
  const [message, setMessage] = useState<string | null>(null);
  const [shouldFetch, setShouldFetch] = useState<boolean>(false); 

  useEffect(() => {
    if (shouldFetch) {
      fetch('/api/generate/ssp') // Uses /api/ as proxy for flask:5000 as stated in vite.config.js
        .then(response => {
          if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
          }
          return response.json();
        })
        .then(jsonData => setMessage(jsonData.message))
        .catch(error => {
          console.error('Error fetching data:', error);
          setMessage('Error fetching data');
        });
    }
  }, [shouldFetch]);

  const handleGenerateTemplate = () => {
    setShouldFetch(true);
  };

  return (
    <Box as="div" className="main-content">
      <Heading>Generate Template</Heading>
      <p>This is the Generate Template page.</p>
      <FileUploader />
      {/*<Button onClick={handleGenerateTemplate} style={{ marginTop: '20px' }}>Generate Template</Button>*/}
      {message && <p>{message}</p>}
    </Box>
  );
};

export default GenerateTemplate;
