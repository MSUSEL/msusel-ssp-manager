import React, { useState, useEffect } from 'react';
import Box from './components/Box';
import './styles/Dashboard.css';

const Dashboard = () => {
  const [data, setData] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const response = await fetch('/example.json'); // Ensure this path points to the correct JSON file
      const jsonData = await response.json();
      setData(jsonData);
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
