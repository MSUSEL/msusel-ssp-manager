import React, { useState, useEffect } from 'react';
import IssueDetails from './IssueDetails'; // Import the component

// Define the interface for a single vulnerability object
interface VulnerabilityData {
  function: string;
  line_number: number[];
  issue_text: string[];
  issue_severity: string[];
  issue_confidence: string[];
  issue_cwe: { id: number; link: string }[];
  more_info: string[];
  filename: string;
}

const VulnerableFunctions: React.FC = () => {
  const [vulnerabilityList, setVulnerabilityList] = useState<VulnerabilityData[] | null>(null);

  useEffect(() => {
    fetch('/api/vulnerable/vulnerable_functions') // Fetch the data from your backend
      .then(response => response.json())
      .then(data => setVulnerabilityList(data)) // Set the fetched array data in state
      .catch(error => console.error('Error fetching vulnerability data:', error));
  }, []);

  if (!vulnerabilityList) {
    return <div>Loading...</div>; // Display a loading message while fetching
  }

  return <IssueDetails data={vulnerabilityList} />; // Pass the array of vulnerability data to IssueDetails
};

export default VulnerableFunctions;
