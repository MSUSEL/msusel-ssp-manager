import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { Box, Heading, Flex } from '@radix-ui/themes';
import Header from './Header';
import Navbar from './Navbar';
import Sidebar from './Sidebar';
import './MainContent.css';

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
    <Box as="div" className="main-content">
      <Heading>Main Content</Heading>
      {data ? <Box>{data}</Box> : <Box>Loading...</Box>}
    </Box>
  );
};

// MainContent component (includes Router, Navbar, and Routes)
const MainContent: React.FC = () => {
  return (
    <Router>
      <Header />
      <Navbar />
      <Flex className="content-container">
        <Sidebar />
        <Routes>
          <Route path="/" element={<Home />} />
          {/* Add more routes as needed */}
        </Routes>
      </Flex>
    </Router>
  );
};

export default MainContent;
