import React, { useEffect, useState, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const ThreatGraph = ({ highlightedNodeId }) => {
  const [data, setData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const containerRef = useRef();
  const fgRef = useRef();
  const hasZoomedRef = useRef(false);

  useEffect(() => {
    fetch('http://127.0.0.1:8000/api/cves/graph')
      .then(res => res.json())
      .then(data => {
        if (data && data.nodes && data.links) setData(data);
        else console.error("Expected graph data but got:", data);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  // Zoom to node when highlighted
  useEffect(() => {
    if (highlightedNodeId && fgRef.current && data.nodes.length > 0) {
      const node = data.nodes.find(n => n.id === highlightedNodeId);
      if (node && node.x !== undefined && node.y !== undefined) {
        hasZoomedRef.current = true;
        fgRef.current.centerAt(node.x, node.y, 800); // 800ms transition
        fgRef.current.zoom(5, 800);
      }
    } else if (!highlightedNodeId && fgRef.current && data.nodes.length > 0 && hasZoomedRef.current) {
      // Reset view only when highlight is cleared AFTER it was zoomed
      hasZoomedRef.current = false;
      fgRef.current.zoomToFit(800, 50); 
    }
  }, [highlightedNodeId, data.nodes]);

  return (
    <div className="glass-panel" style={{ height: '500px', overflow: 'hidden', position: 'relative' }} ref={containerRef}>
      <div className="label-small" style={{ position: 'absolute', top: '15px', left: '15px', zIndex: 10 }}>Threat Intelligence Graph</div>
      {loading ? (
        <div className="skeleton" style={{ height: '100%', width: '100%' }}></div>
      ) : (
        <ForceGraph2D
          ref={fgRef}
          graphData={data}
          nodeLabel="id"
          nodeAutoColorBy="type"
          nodeCanvasObject={(node, ctx, globalScale) => {
            const label = node.id;
            const fontSize = 12 / globalScale;
            ctx.font = `${fontSize}px DM Sans`;
            const textWidth = ctx.measureText(label).width;
            const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

            const isHighlighted = highlightedNodeId === node.id;
            const isDimmed = highlightedNodeId && !isHighlighted;

            ctx.fillStyle = isDimmed ? 'rgba(13, 27, 42, 0.2)' : 'rgba(13, 27, 42, 0.8)';
            if (isHighlighted) {
                ctx.strokeStyle = 'var(--accent-gold)';
                ctx.lineWidth = 2 / globalScale;
                ctx.strokeRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);
            }
            ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);

            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = isDimmed ? 'rgba(255, 255, 255, 0.1)' : node.color;
            ctx.fillText(label, node.x, node.y);
          }}
          linkColor={() => 'var(--border)'}
          backgroundColor="transparent"
          width={containerRef.current?.offsetWidth || 800}
          height={500}
        />
      )}
    </div>
  );
};

export default ThreatGraph;
