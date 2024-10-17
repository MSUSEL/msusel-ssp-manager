import React, { useState, useEffect } from 'react';
import IssueDetails from './IssueDetails'; // Import the component

const VulnerableFunctions: React.FC = () => {
  const [issueData, setIssueData] = useState<IssueData | null>(null);

  useEffect(() => {
    fetch('/api/vulnerable/vulnerable_functions') // Fetch the data from your backend
      .then(response => response.json())
      .then(data => setIssueData(data)) // Set the fetched data in state
      .catch(error => console.error('Error fetching issue data:', error));
  }, []);

  if (!issueData) {
    return <div>Loading...</div>; // Display a loading message while fetching
  }

  return <IssueDetails data={issueData} />; // Pass the fetched data to IssueDetails
};

export default VulnerableFunctions;
