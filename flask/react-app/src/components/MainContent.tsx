import React, { useEffect, useState } from 'react';

const MainContent: React.FC = () => {
  const [data, setData] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/data')
      .then(response => {
        console.log('Response:', response); // Log the response for debugging
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.text(); // Get the response as text for debugging
      })
      .then(text => {
        console.log('Response Text:', text); // Log the response text for debugging
        const jsonData = JSON.parse(text); // Parse the JSON from the text
        setData(jsonData.message);
      })
      .catch(error => {
        console.error('Error fetching data:', error);
        setData('Error fetching data');
      });
  }, []);

  return (
    <div>
      <h1>Main Content</h1>
      {data ? <p>{data}</p> : <p>Loading...</p>}
    </div>
  );
};

export default MainContent;
