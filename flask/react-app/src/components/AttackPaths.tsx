import React, { useEffect, useState } from 'react';

const AttackPaths: React.FC = () => {
  const [htmlUrl, setHtmlUrl] = useState<string>('');

  useEffect(() => {
    const fetchHtml = async () => {
      try {
        console.log('Starting to fetch HTML content...');

        const response = await fetch('/api/getPaths/network_flow'); // Adjust URL as needed
        console.log(`Received response with status: ${response.status}`);

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        setHtmlUrl(url);
      } catch (error) {
        console.error('Error fetching HTML:', error);
      }
    };

    fetchHtml();
  }, []);

  const containerStyle = {
    width: '100%',
    height: 'calc(100vh - 100px)', // Adjust the height as needed to fit your layout
    border: '1px solid #ddd', // Optional: border styling
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center'
  };

  const iframeStyle = {
    width: '95%', // Adjust the width as needed
    height: '95%', // Adjust the height as needed
    border: '1px solid #ddd', // Optional: border styling
    boxSizing: 'border-box',
    overflow: 'hidden' // Hides any overflow to keep the content tidy
  };

  return (
    <div style={containerStyle}>
      <h2> Attack Paths</h2>
      {htmlUrl ? (
        <iframe
          src={htmlUrl}
          style={iframeStyle}
          loading="lazy"
          title="Pyvis Graph"
        />
      ) : (
        <p>Loading graph...</p>
      )}
    </div>
  );
};

export default AttackPaths;
