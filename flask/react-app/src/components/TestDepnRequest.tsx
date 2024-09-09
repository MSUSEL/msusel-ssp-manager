import React, { useState } from 'react';

interface TestDepnRequestProps {
  apiEndpoint: string;
}

const TestDepnRequest: React.FC<TestDepnRequestProps> = ({ apiEndpoint }) => {
  const [output, setOutput] = useState<string[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [vulnerabilityEffectivenessResults, setvulnerabilityEffectivenessResults] = useState<any | null>(null); // Changed to 'any' to handle JSON

  const handleFetch = async () => {
    setLoading(true);
    try {
      const response = await fetch(apiEndpoint);
      if (response.ok) {
        const resultText = await response.json(); // Parse JSON response
        setvulnerabilityEffectivenessResults(resultText);
      }
    } catch (error) {
      setOutput([`Error: ${error.message}`]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <button onClick={handleFetch} 
	style={{ 
          backgroundColor: '#007bff', 
          color: 'white', 
          padding: '10px 20px', 
          border: 'none', 
          borderRadius: '4px', 
          cursor: 'pointer',
          marginRight: '10px'
        }}
	disabled={loading}>
        {loading ? 'Loading...' : 'Test Dependencies'}
      </button>
      <div>
        {vulnerabilityEffectivenessResults && (
        <div style={{ marginTop: '20px', padding: '10px', border: '1px solid #ccc', borderRadius: '5px' }}>
          <h3>Vulnerability Effectiveness Results:</h3>
          <h4>Output:</h4>
          <ul style={{ listStyleType: 'disc', marginLeft: '20px', marginBottom: '10px' }}>
            {vulnerabilityEffectivenessResults.message}
          </ul>
        </div>
      )}
      </div>
    </div>
  );
};

export default TestDepnRequest;
