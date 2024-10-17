import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { Network } from 'vis-network/standalone';

interface Node {
  id: number | string;  // Modified to handle string IDs like 'Start'
  label: string;
  x?: number;           // Optional x position for fixed nodes
  y?: number;           // Optional y position for fixed nodes
  fixed?: boolean;      // Optional fixed positioning flag
}

interface Edge {
  from: number | string;
  to: number | string;
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
        const data = response.data;

        // Modify specific nodes to fix their positions
        const modifiedNodes = data.nodes.map((node: Node) => {
          if (node.label === 'Start') {
            return { ...node, x: -500, y: 0, fixed: true }; // Fix 'Start' node to the left
          }
          if (node.label === 'End') {
            return { ...node, x: 500, y: 0, fixed: true };  // Fix 'End' node to the right
          }
          return node;  // Return other nodes as they are
        });

        setGraphData({ nodes: modifiedNodes, edges: data.edges });
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
          size: 5,  // Node size
          shape: 'dot',  // Dots instead of ellipses
          color: {
            border: '#000000',
            background: '#ffffff',
          },
          font: {
            color: '#000000',
            size: 14,  // Font size
            multi: true,  // Multiline support for labels
            vadjust: -10,  // Vertically adjust the label
            face: 'arial', // Font type
          },
        },
        edges: {
          color: 'blue',
          length: 100,  // Edge length
          width: 1,  // Thinner edges
          smooth: true,  // Smooth edges
        },
        physics: {
          forceAtlas2Based: {
            gravitationalConstant: -100,
            centralGravity: 0.005,
            springLength: 100,
            damping: 0.4,
          },
          maxVelocity: 10,  // Max velocity of nodes
        },
        layout: {
          improvedLayout: true,  // For a cleaner layout
          hierarchical: false,   // Ensure hierarchical is disabled
        },
        manipulation: {
          enabled: false,
        },
      };

      const network = new Network(visJsRef.current, data, options);

      // Set an initial zoom level
      network.moveTo({
        scale: 1,
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
