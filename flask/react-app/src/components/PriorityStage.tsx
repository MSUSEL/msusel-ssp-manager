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
  const networkRef = useRef<Network | null>(null);
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
          size: 5,  // Node size
          shape: 'dot',  // Dots instead of ellipses
          color: {
            border: '#ffffff',
            background: '#120BEF',
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

export default PriorityStage;
