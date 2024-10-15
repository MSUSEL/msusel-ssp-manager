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
        interaction: { hover: true },
        nodes: {
          shape: 'ellipse',
          color: {
            border: '#000000',
            background: '#ffffff',
          },
          font: { color: '#000000' },
        },
        edges: {
          color: 'blue',
        },
      };

      const network = new Network(visJsRef.current, data, options);

      // Event handler for node click
      network.on('click', function (params) {
        if (params.nodes.length > 0) {
          alert(`Node clicked: ${params.nodes[0]}`);
        }
      });
    }
  }, [graphData]);

  return (
    <div>
      <h2>Dynamic Graph</h2>
      {graphData ? (
        <div ref={visJsRef} style={{ height: '400px', width: '600px', border: '1px solid black' }}></div>
      ) : (
        <p>Loading graph data...</p>
      )}
    </div>
  );
};

export default Tactics;
