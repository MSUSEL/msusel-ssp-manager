import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import { Box, Heading } from '@radix-ui/themes';

// Navbar component
const Navbar: React.FC = () => {
  return (
    <Box as="nav" style={{ padding: '20px', backgroundColor: 'lightgray' }}>
      <Link to="/">Home</Link>
    </Box>
  );
};

// Home component (fetches data from the Flask backend)
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
    <Box as="div" style={{ padding: '20px', flex: '1' }}>
      <Heading>Main Content</Heading>
      {data ? <Box>{data}</Box> : <Box>Loading...</Box>}
    </Box>
  );
};

// MainContent component (includes Router, Navbar, and Routes)
const MainContent: React.FC = () => {
  return (
    <Router>
      <Navbar />
      <Routes>
        <Route path="/" element={<Home />} />
      </Routes>
    </Router>
  );
};

export default MainContent;
