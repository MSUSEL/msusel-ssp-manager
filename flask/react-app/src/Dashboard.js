import React, { useState, useEffect } from 'react';
import Box from './components/Box';
import './styles/Dashboard.css';

const Dashboard = () => {
  const [data, setData] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch('/example.json'); // The proxy will redirect this to http://localhost:5000/example.json
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        const jsonData = await response.json();
        setData(jsonData);
      } catch (error) {
        console.error('Error fetching data:', error);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="dashboard-container">
      {data.map((item) => (
        <Box key={item.id} data={item} />
      ))}
    </div>
  );
};

export default Dashboard;
