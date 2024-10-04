import React, { useEffect, useState, useRef } from 'react';

const AttackTechniques: React.FC = () => {
  const [htmlUrl, setHtmlUrl] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    const fetchHtml = async () => {
      try {
        console.log('Starting to fetch HTML content...');

        const response = await fetch(`/api/getGraph/graph?timestamp=${new Date().getTime()}`);
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

  // Function to handle iframe load event
  const handleIframeLoad = () => {
    console.log('Iframe has loaded successfully.');
    setLoading(false); // Set loading to false once the iframe content has loaded
  };

  const containerStyle = {
    width: '100%',
    height: 'calc(100vh - 100px)', // Adjust to match the graph height
    border: '1px solid #ddd',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
  };

  const iframeStyle = {
    width: '100%',
    height: '100%',
    border: 'none',
    overflow: 'hidden',
  };

  return (
    <div style={containerStyle}>
      <h2>Attack Techniques</h2>
      {loading && <p>Loading graph...</p>}
      {htmlUrl && (
        <iframe
          ref={iframeRef}
          src={htmlUrl}
          style={iframeStyle}
          loading="lazy"
          title="Pyvis Graph"
          onLoad={handleIframeLoad} // Attach onLoad event handler
        />
      )}
    </div>
  );
};

export default AttackTechniques;
