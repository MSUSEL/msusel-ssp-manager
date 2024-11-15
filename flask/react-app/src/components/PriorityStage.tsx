import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { Network } from 'vis-network/standalone';

interface Node {
  id: number;
  label: string;
}

interface Edge {
  from: number;
  to: number;
}

interface GraphData {
  nodes: Node[];
  edges: Edge[];
}

const PriorityStage: React.FC = () => {
  const visJsRef = useRef<HTMLDivElement | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);

  // Fetch graph data from the backend
  useEffect(() => {
    const fetchGraphData = async () => {
      try {
        const response = await axios.get('/api/tactics/graph_data');
        setGraphData(response.data);
      } catch (error) {
        console.error('Error fetching graph data:', error);
      }
    };
    fetchGraphData();
  }, []);

  useEffect(() => {
    if (graphData && visJsRef.current) {
      const { nodes, edges } = graphData;

      const data = {
        nodes,
        edges,
      };

      const options = {
        interaction: {
          hover: true,
          zoomView: true,  // Enable zooming
        },
        nodes: {
          shape: 'ellipse',
          color: {
            border: '#000000',
            background: '#ffffff',
          },
          font: {
            color: '#000000',
            size: 20, // Further increase the font size
            face: 'arial', // Choose a clear and readable font
          },
        },
        edges: {
          color: 'blue',
        },
        physics: {
          enabled: true,  // Enable physics for better node layout
        },
        // Initial zoom level
        scale: 1,  // Zoom in more to improve visibility of labels
        // Control zoom limits
        manipulation: {
          enabled: false,
        },
      };

      const network = new Network(visJsRef.current, data, options);

      // Set an initial zoom level (zoom in more)
      network.moveTo({
        scale: 1,  // Adjust this value to zoom in more by default
      });
    }
  }, [graphData]);

  return (
    <div style={{ width: '100%', height: '80vh', padding: '20px' }}>
      <h2> </h2>
      {graphData ? (
        <div ref={visJsRef} style={{ height: '100%', width: '100%', backgroundColor: '#121212', border: '5px solid black', borderRadius: '10px', boxShadow: '0px 4px 10px rgba(0, 0, 0, 0.8), 0px 8px 20px rgba(0, 0, 0, 0.5)' }}></div>
      ) : (
        <p>Loading graph data...</p>
      )}
    </div>
  );
};

export default PriorityStage;
