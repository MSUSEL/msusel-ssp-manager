import React, { useEffect, useState } from 'react';
import { Box, Heading } from '@radix-ui/themes';

const Home: React.FC = () => {
  const [data, setData] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/data')
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(jsonData => setData(jsonData.message))
      .catch(error => {
        console.error('Error fetching data:', error);
        setData('Error fetching data');
      });
  }, []);

  return (
    <Box as="div" className="main-content">
      <Heading>Main Content</Heading>
      {data ? <Box>{data}</Box> : <Box>Loading...</Box>}
    </Box>
  );
};

export default Home;
