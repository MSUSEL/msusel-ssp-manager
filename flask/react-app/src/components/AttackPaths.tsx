import React, { useEffect, useRef, useState } from 'react';
import axios from 'axios';
import { Network } from 'vis-network/standalone';

interface Node {
  id: number | string;
  label: string;
  x?: number;
  y?: number;
  fixed?: boolean;
  color?: {
    background?: string;
    border?: string;
  };
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
  const networkRef = useRef<Network | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);

  // Fetch graph data from the backend
  useEffect(() => {
    const fetchGraphData = async () => {
      try {
        const response = await axios.get('/api/attack/attack_paths');
        const data = response.data;
        console.log('Received data from backend:', data); // Debug log

        // Modify specific nodes to fix their positions and preserve colors
        const modifiedNodes = data.nodes.map((node: Node) => {
          let nodeConfig = { ...node };
          
          // Fix positions for Start and End nodes
          if (node.label === 'Start') {
            nodeConfig = { ...nodeConfig, x: -500, y: 0, fixed: true };
          }
          if (node.label === 'End') {
            nodeConfig = { ...nodeConfig, x: 500, y: 0, fixed: true };
          }
          
          // Ensure color information is preserved
          if (node.color && typeof node.color === 'object') {
            // Color is already an object with background/border
            nodeConfig.color = node.color;
          } else if (node.color === 'red') {
            // Color is a string 'red'
            nodeConfig.color = {
              background: '#FF0000',
              border: '#000000'
            };
          }
          
          return nodeConfig;
        });

        console.log('Modified nodes:', modifiedNodes); // Debug log
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
      console.log('Rendering graph with nodes:', nodes); // Debug log

      const data = {
        nodes,
        edges,
      };

      const options = {
        interaction: {
          tooltipDelay: 0, // Disable the tooltip box
          hover: true,
          zoomView: true,  // Enable zooming
        },
        nodes: {
          size: 5,  // Node size
          shape: 'dot',  // Dots instead of ellipses
          color: {
            border: '#ffffff',
            background: '#120BEF',
            highlight: {
              border: '#ffffff',
              background: '#120BEF'
            }
          },
          font: {
            color: '#ffffff',
            size: 14,  // Font size
            multi: true,  // Multiline support for labels
            vadjust: -10,  // Vertically adjust the label
            face: 'arial', // Font type
          },
        },
        edges: {
          color: '#0910DF',
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
      networkRef.current = network; // Store network reference

      // Set an initial zoom level
      network.moveTo({
        scale: 1,
      });
    }
  }, [graphData]);

  // Zoom handlers
  const handleZoomIn = () => {
    if (networkRef.current) {
      const currentScale = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: currentScale * 1.2 });
    }
  };

  const handleZoomOut = () => {
    if (networkRef.current) {
      const currentScale = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: currentScale * 0.8 });
    }
  };

  const handleFitGraph = () => {
    if (networkRef.current) {
      networkRef.current.fit();
    }
  };

  return (
    <div style={{ width: '100%', height: '80vh', padding: '20px' }}>
      <h2> </h2>
      {graphData ? (
        <>
          <div style={{ marginBottom: '10px' }}>
            <button onClick={handleZoomIn} style={{ marginRight: '5px' }}>Zoom In</button>
            <button onClick={handleZoomOut} style={{ marginRight: '5px' }}>Zoom Out</button>
            <button onClick={handleFitGraph}>Fit Graph</button>
          </div>
          <div ref={visJsRef} style={{ height: '100%', width: '100%', backgroundColor: '#121212', border: '5px solid black', borderRadius: '10px', boxShadow: '0px 4px 10px rgba(0, 0, 0, 0.8), 0px 8px 20px rgba(0, 0, 0, 0.5)' }}></div>
        </>
      ) : (
        <p>Loading graph data...</p>
      )}
    </div>
  );
};

export default AttackPaths;
