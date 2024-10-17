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

const AttackPaths: React.FC = () => {
  const visJsRef = useRef<HTMLDivElement | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);

  // Fetch graph data from the backend
  useEffect(() => {
    const fetchGraphData = async () => {
      try {
        const response = await axios.get('/api/attack/attack_paths');
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
          size: 5,  // Increase the node size
          shape: 'dot',  // Use dots instead of ellipses for nodes
          color: {
            border: '#000000',
            background: '#ffffff',
          },
          font: {
            color: '#000000',
            size: 14,  // Reduce font size
            multi: true,  // Enable multiline labels if needed
            vadjust: -10,  // Vertically adjust label positioning to avoid overlap
            face: 'arial', // Choose a clear and readable font
          },
        },
        edges: {
          color: 'blue',
          length: 100,  // Increase the length of the edges
          width: 1,  // Thinner edges for better readability
          smooth: true,  // Add smooth edges for a cleaner look
        },
        physics: {
          forceAtlas2Based: {
            gravitationalConstant: -100,  // Adjust to control node clustering
            centralGravity: 0.005,       // How strongly nodes are pulled towards the center
            springLength: 100,           // Distance between connected nodes (length of the edges)
            damping: 0.4,                // Adjust to make the nodes settle faster
          },
          maxVelocity: 10,  // Reduce the maximum velocity of nodes
        },
        layout: {
          improvedLayout: true,  // Optional: for a cleaner, spread-out layout
          hierarchical: false,
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
    <div style={{ width: '100%', height: '80vh', padding: '20px' }}>
      <h2>Attack Paths</h2>
      {graphData ? (
        <div ref={visJsRef} style={{ height: '100%', width: '100%', border: '1px solid black' }}></div>
      ) : (
        <p>Loading graph data...</p>
      )}
    </div>
  );
};

export default AttackPaths;
