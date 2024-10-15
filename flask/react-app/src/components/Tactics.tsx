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

const Tactics: React.FC = () => {
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

      // Event handler for node click
      network.on('click', function (params) {
        if (params.nodes.length > 0) {
          alert(`Node clicked: ${params.nodes[0]}`);
        }
      });
    }
  }, [graphData]);

  return (
    <div style={{ width: '75%', height: '80vh', padding: '20px' }}>
      <h2>Dynamic Graph</h2>
      {graphData ? (
        <div ref={visJsRef} style={{ height: '75%', width: '75%', border: '1px solid black' }}></div>
      ) : (
        <p>Loading graph data...</p>
      )}
    </div>
  );
};

export default Tactics;
