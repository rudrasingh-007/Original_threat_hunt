import React, { useEffect, useState, useRef, useMemo, useLayoutEffect } from 'react';
import './App.css';
import ForceGraph2D from 'react-force-graph-2d';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000';

// Custom hook to measure container dimensions, supporting conditionally mounted elements
function useResizeObserver() {
  const [size, setSize] = useState({ width: 0, height: 0 });
  const observerRef = useRef(null);

  const ref = React.useCallback((node) => {
    if (observerRef.current) {
      observerRef.current.disconnect();
      observerRef.current = null;
    }
    if (node) {
      observerRef.current = new ResizeObserver(entries => {
        if (!Array.isArray(entries) || !entries.length) return;
        const { width, height } = entries[0].contentRect;
        setSize({ width, height });
      });
      observerRef.current.observe(node);
    }
  }, []);

  return [ref, size];
}

const NODE_TYPES = ['Host', 'User', 'Hash', 'IP'];
const NODE_COLORS = {
  Host: '#22c55e',
  User: '#3b82f6',
  Hash: '#f59e0b',
  IP: '#a855f7'
};

export default function App() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [apiError, setApiError] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [hypothesis, setHypothesis] = useState('');
  const [loadingAI, setLoadingAI] = useState(false);
  const [typeFilters, setTypeFilters] = useState({ Host: true, User: true, Hash: true, IP: true });
  const [searchQuery, setSearchQuery] = useState('');
  const [activeView, setActiveView] = useState('graph'); // 'graph' | 'timeline' | 'replay'
  const [relFilter, setRelFilter] = useState('ALL'); // ALL | LOGGED_INTO | CONNECTED_TO | RAN
  const [threatOnly, setThreatOnly] = useState(false);
  const [blastRadiusData, setBlastRadiusData] = useState(null);
  const [riskPropagation, setRiskPropagation] = useState({}); // { nodeId: 'compromised' | 'high' | 'medium' | 'low' }
  const [replayData, setReplayData] = useState({ nodes: [], links: [] });
  const [replayProgress, setReplayProgress] = useState(0); // 0 to 1
  const [isPlaying, setIsPlaying] = useState(false);
  const [replayInterval, setReplayInterval] = useState(null);
  const [pathMode, setPathMode] = useState(false);
  const [pathSource, setPathSource] = useState(null);
  const [pathTarget, setPathTarget] = useState(null);
  const [attackPath, setAttackPath] = useState(null);
  const fgRef = useRef();
  const hasInitialFit = useRef(false);

  // Ref for the replay container
  const [replayContainerRef, replayContainerSize] = useResizeObserver();

  useEffect(() => {
    axios.get(`${API_BASE_URL}/api/graph`)
      .then(res => {
        setApiError('');
        const nodes = res.data.nodes.map(n => ({
          label: n.label,
          name: n.properties?.name || n.properties?.address || n.properties?.value || String(n.id),
          ...n.properties,
          id: n.id // must match link source/target; set last so it isn't overwritten by spread
        }));
        const nodeMap = new Map(nodes.map(n => [n.id, n]));
        const links = res.data.links
          .filter(l => nodeMap.has(l.source) && nodeMap.has(l.target))
          .map(l => ({
            source: nodeMap.get(l.source),
            target: nodeMap.get(l.target),
            type: l.type
          }));
        setGraphData({ nodes, links });

        // Prepare replay data - sort nodes by timestamp
        const sortedNodes = [...nodes].sort((a, b) => {
          const aTime = a.timestamp ? new Date(a.timestamp).getTime() : 0;
          const bTime = b.timestamp ? new Date(b.timestamp).getTime() : 0;
          return aTime - bTime;
        });
        setReplayData({ nodes: sortedNodes, links });

        // Stabilize layout after initial data load
        setTimeout(() => {
          if (fgRef.current) {
            fgRef.current.d3Force('charge').strength(-120);
            fgRef.current.d3Force('link').distance(70);
            fgRef.current.d3Force('x', null);
            fgRef.current.d3Force('y', null);
            fgRef.current.d3ReheatSimulation();
          }
        }, 100);
      })
      .catch(() => {
        setApiError(`Unable to connect to API at ${API_BASE_URL}. Start the backend server and refresh.`);
        setGraphData({ nodes: [], links: [] });
        setReplayData({ nodes: [], links: [] });
      });
  }, []);

  const isNodeThreat = (node) => node.malicious === true || node.suspicious === true;

  const filteredGraphData = useMemo(() => {
    const visibleTypes = Object.entries(typeFilters).filter(([, v]) => v).map(([k]) => k);
    const filteredNodes = graphData.nodes.filter(
      n => visibleTypes.includes(n.label) && (!threatOnly || isNodeThreat(n))
    );
    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const sourceId = (l) => typeof l.source === 'object' ? l.source.id : l.source;
    const targetId = (l) => typeof l.target === 'object' ? l.target.id : l.target;
    const filteredLinks = graphData.links.filter(l => {
      const sId = sourceId(l);
      const tId = targetId(l);
      if (!nodeIds.has(sId) || !nodeIds.has(tId)) return false;
      if (relFilter === 'ALL') return true;
      return l.type === relFilter;
    });
    return { nodes: filteredNodes, links: filteredLinks };
  }, [graphData, typeFilters, relFilter, threatOnly]);

  const searchMatches = useMemo(() => {
    if (!searchQuery.trim()) return new Set();
    const q = searchQuery.toLowerCase().trim();
    return new Set(
      filteredGraphData.nodes
        .filter(n => String(n.name || '').toLowerCase().includes(q))
        .map(n => n.id)
    );
  }, [filteredGraphData, searchQuery]);

  const timelineItems = useMemo(() => {
    const nodes = graphData.nodes || [];
    return [...nodes].sort((a, b) => {
      const ta = a.timestamp ? Date.parse(a.timestamp) : NaN;
      const tb = b.timestamp ? Date.parse(b.timestamp) : NaN;
      const aHas = Number.isFinite(ta);
      const bHas = Number.isFinite(tb);
      if (!aHas && !bHas) return 0;
      if (!aHas) return 1;
      if (!bHas) return -1;
      return ta - tb;
    });
  }, [graphData.nodes]);

  const timelineSummary = useMemo(() => {
    const nodes = graphData.nodes || [];
    let malicious = 0;
    let suspicious = 0;
    nodes.forEach(n => {
      if (n.malicious) malicious += 1;
      if (n.suspicious) suspicious += 1;
    });
    return {
      total: nodes.length,
      malicious,
      suspicious
    };
  }, [graphData.nodes]);

  // Attack replay computed values
  const replayGraphData = useMemo(() => {
    if (!replayData.nodes.length) return { nodes: [], links: [] };

    // Ensure we start with at least 1 node instead of an empty screen
    const nodeCount = Math.max(1, Math.floor(replayProgress * replayData.nodes.length));
    const visibleNodes = replayData.nodes.slice(0, nodeCount);
    const visibleNodeIds = new Set(visibleNodes.map(n => n.id));

    // Only show links where both source and target are visible
    const visibleLinks = replayData.links.filter(link =>
      visibleNodeIds.has(link.source.id) && visibleNodeIds.has(link.target.id)
    );

    return { nodes: visibleNodes, links: visibleLinks };
  }, [replayData, replayProgress]);

  const replayStats = useMemo(() => {
    const visibleCount = replayGraphData.nodes.length;
    const currentNode = replayGraphData.nodes[visibleCount - 1];
    const currentTimestamp = currentNode?.timestamp || 'Start';

    // Create morphology curve data (node count over time)
    const curveData = replayData.nodes.map((node, index) => ({
      x: index / replayData.nodes.length,
      y: (index + 1) / replayData.nodes.length
    }));

    return {
      visibleCount,
      currentTimestamp,
      curveData
    };
  }, [replayGraphData, replayData]);

  const typeCounts = useMemo(() => {
    const counts = {};
    (graphData.nodes || []).forEach(n => {
      if (!n.label) return;
      counts[n.label] = (counts[n.label] || 0) + 1;
    });
    return counts;
  }, [graphData.nodes]);

  const toggleTypeFilter = (type) => {
    setTypeFilters(prev => ({ ...prev, [type]: !prev[type] }));
  };

  const isMaliciousOrSuspicious = (node) => isNodeThreat(node);

  const generateHypothesis = () => {
    setLoadingAI(true);
    setHypothesis('');
    axios.get(`${API_BASE_URL}/api/hypothesis`)
      .then(res => {
        setApiError('');
        setHypothesis(res.data.hypothesis);
        setLoadingAI(false);
      })
      .catch(() => {
        setApiError(`Unable to connect to API at ${API_BASE_URL}.`);
        setLoadingAI(false);
      });
  };

  const simulateCompromise = () => {
    if (!selectedNode || !blastRadiusData) return;

    // Clear any existing simulation
    setRiskPropagation({});

    // Start with compromised node
    setRiskPropagation({ [selectedNode.id]: 'compromised' });

    // After 1 second, add high risk (depth 1)
    setTimeout(() => {
      setRiskPropagation(prev => {
        const newRisk = { ...prev };
        Object.entries(blastRadiusData.node_depths).forEach(([nodeId, depth]) => {
          if (depth === 1) newRisk[nodeId] = 'high';
        });
        return newRisk;
      });
    }, 1000);

    // After 2 seconds, add medium risk (depth 2)
    setTimeout(() => {
      setRiskPropagation(prev => {
        const newRisk = { ...prev };
        Object.entries(blastRadiusData.node_depths).forEach(([nodeId, depth]) => {
          if (depth === 2) newRisk[nodeId] = 'medium';
        });
        return newRisk;
      });
    }, 2000);

    // After 3 seconds, add low risk (depth 3)
    setTimeout(() => {
      setRiskPropagation(prev => {
        const newRisk = { ...prev };
        Object.entries(blastRadiusData.node_depths).forEach(([nodeId, depth]) => {
          if (depth === 3) newRisk[nodeId] = 'low';
        });
        return newRisk;
      });
    }, 3000);
  };

  const resetSimulation = () => {
    setRiskPropagation({});
  };

  // Handle autoplay interval via useEffect
  useEffect(() => {
    let interval = null;
    if (isPlaying) {
      interval = setInterval(() => {
        setReplayProgress(prev => {
          const next = prev + 0.01; // Advance by 1%
          if (next >= 1) {
            setIsPlaying(false);
            return 1;
          }
          return next;
        });
      }, 800); // 800ms speed for smoother, slower replay
    } else if (!isPlaying && interval) {
      clearInterval(interval);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isPlaying]);

  const startReplay = () => {
    if (replayProgress >= 1) {
      setReplayProgress(0); // auto-restart if at end
    }
    setIsPlaying(true);
  };

  const pauseReplay = () => {
    setIsPlaying(false);
  };

  const resetReplay = () => {
    setIsPlaying(false);
    setReplayProgress(0);
  };

  const handlePathModeNodeClick = (node) => {
    if (!pathMode) return false;

    if (!pathSource) {
      setPathSource(node);
      return true;
    }

    if (!pathTarget) {
      setPathTarget(node);
      // Call API to get attack path
      axios.get(`${API_BASE_URL}/api/attack-path/${pathSource.id}/${node.id}`)
        .then(res => {
          // Expecting shape: { found: boolean, hops: number, path_nodes: string[] }
          setApiError('');
          setAttackPath(res.data);
        })
        .catch(err => {
          console.error('Attack path error:', err);
          setApiError(`Unable to connect to API at ${API_BASE_URL}.`);
          setAttackPath({ found: false, path_nodes: [], hops: 0 });
        });
      return true;
    }

    // Reset for next path on third click
    setPathSource(node);
    setPathTarget(null);
    setAttackPath(null);
    return true;
  };

  const togglePathMode = () => {
    const newMode = !pathMode;
    setPathMode(newMode);
    if (!newMode) {
      // Clear everything when turning off
      setPathSource(null);
      setPathTarget(null);
      setAttackPath(null);
    }
  };

  const neighborIds = useMemo(() => {
    if (!selectedNode) return new Set();
    const set = new Set([selectedNode.id]);
    const sourceId = (l) => typeof l.source === 'object' ? l.source.id : l.source;
    const targetId = (l) => typeof l.target === 'object' ? l.target.id : l.target;
    (graphData.links || []).forEach(l => {
      const sId = sourceId(l);
      const tId = targetId(l);
      if (sId === selectedNode.id) set.add(tId);
      if (tId === selectedNode.id) set.add(sId);
    });
    return set;
  }, [graphData.links, selectedNode]);

  const attackPathNodeSet = useMemo(() => {
    return new Set(attackPath?.path_nodes || []);
  }, [attackPath]);

  const attackPathIndexById = useMemo(() => {
    const map = new Map();
    if (!attackPath || !attackPath.path_nodes) return map;
    attackPath.path_nodes.forEach((id, index) => {
      map.set(id, index);
    });
    return map;
  }, [attackPath]);

  const formatTimestamp = (ts) => {
    if (!ts) return 'Unknown time';
    const d = new Date(ts);
    if (!Number.isFinite(d.getTime())) return 'Unknown time';
    return d.toLocaleString('en-US', {
      month: 'short',
      day: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  };

  // Auto-focus graph on first search match
  useEffect(() => {
    if (!fgRef.current) return;
    if (!searchQuery.trim()) return;

    const firstId = [...searchMatches][0];
    if (!firstId) return;

    const node = filteredGraphData.nodes.find(n => n.id === firstId);
    if (!node) return;

    const { x, y } = node;
    if (!Number.isFinite(x) || !Number.isFinite(y)) return;

    fgRef.current.centerAt(x, y, 400);
    fgRef.current.zoom(4, 400);
  }, [searchMatches, filteredGraphData, searchQuery]);

  const paintNode = (node, ctx, globalScale) => {
    const x = node.x;
    const y = node.y;
    const nodeRadius = 6;

    // Guard against uninitialized / non-finite positions during simulation warmup
    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(globalScale)) {
      return;
    }

    const label = node.name || node.id;
    const fontSize = 12 / globalScale;
    ctx.font = `${fontSize}px JetBrains Mono, Fira Code, Consolas, monospace`;

    const isThreat = isMaliciousOrSuspicious(node);
    const isSearchMatch = searchMatches.has(node.id);
    const baseColor = NODE_COLORS[node.label] || '#6b7280';
    const blastRadiusDepth = blastRadiusData?.node_depths?.[node.id];
    const isBlastRadiusNode = blastRadiusDepth !== undefined;
    const riskLevel = riskPropagation[node.id];

    // Attack path visualization
    const isInAttackPath = attackPathNodeSet.has(node.id);
    const isPathSource = pathSource?.id === node.id;
    const isPathTarget = pathTarget?.id === node.id;

    // Determine final node color based on risk level (overrides normal colors)
    let nodeColor = baseColor;
    if (isPathSource) {
      nodeColor = '#22c55e'; // Bright green
    } else if (isPathTarget) {
      nodeColor = '#ef4444'; // Bright red
    } else if (isInAttackPath) {
      nodeColor = '#eab308'; // Bright yellow for path nodes
    } else if (riskLevel) {
      const riskColors = {
        compromised: '#ef4444', // bright red
        high: '#f97316', // solid orange
        medium: '#eab308', // solid yellow
        low: '#a3a308' // dim yellow
      };
      nodeColor = riskColors[riskLevel];

      // Add pulsing effect for compromised nodes
      if (riskLevel === 'compromised') {
        const pulse = Math.sin(Date.now() * 0.01) * 0.3 + 0.7; // Pulse between 0.4 and 1.0
        const [r, g, b] = [239, 68, 68]; // Bright red RGB
        nodeColor = `rgba(${r}, ${g}, ${b}, ${pulse})`;
      }
    }

    ctx.save();

    // Dim non-path nodes when in path mode with path found
    if (pathMode && attackPathNodeSet.size > 0) {
      if (!isInAttackPath && !isPathSource && !isPathTarget) {
        ctx.globalAlpha = 0.15;
      } else {
        ctx.globalAlpha = 1;
      }
    } else if (selectedNode) {
      // Original dimming for selected node neighbors
      const isNeighbor = neighborIds.has(node.id);
      if (!isNeighbor && !isBlastRadiusNode) {
        ctx.globalAlpha = 0.18;
      } else {
        ctx.globalAlpha = 1;
      }
    }

    // Bright yellow glow for nodes in attack path
    if (isInAttackPath && !isPathSource && !isPathTarget) {
      const glowLayers = 4;
      for (let i = glowLayers; i >= 1; i--) {
        const r = nodeRadius + i * 4;
        const gradient = ctx.createRadialGradient(x, y, nodeRadius, x, y, r);
        gradient.addColorStop(0, `rgba(234, 179, 8, ${0.4 - i * 0.08})`);
        gradient.addColorStop(1, 'rgba(234, 179, 8, 0)');
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = gradient;
        ctx.fill();
      }
    }

    // Green glow for path source
    if (isPathSource) {
      const glowLayers = 4;
      for (let i = glowLayers; i >= 1; i--) {
        const r = nodeRadius + i * 4;
        const gradient = ctx.createRadialGradient(x, y, nodeRadius, x, y, r);
        gradient.addColorStop(0, `rgba(34, 197, 94, ${0.4 - i * 0.08})`);
        gradient.addColorStop(1, 'rgba(34, 197, 94, 0)');
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = gradient;
        ctx.fill();
      }
    }

    // Red glow for path target
    if (isPathTarget) {
      const glowLayers = 4;
      for (let i = glowLayers; i >= 1; i--) {
        const r = nodeRadius + i * 4;
        const gradient = ctx.createRadialGradient(x, y, nodeRadius, x, y, r);
        gradient.addColorStop(0, `rgba(239, 68, 68, ${0.4 - i * 0.08})`);
        gradient.addColorStop(1, 'rgba(239, 68, 68, 0)');
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = gradient;
        ctx.fill();
      }
    }

    // Glowing orange border for blast radius nodes
    if (isBlastRadiusNode) {
      const intensityMap = { 1: 0.9, 2: 0.7, 3: 0.5, 4: 0.3 };
      const intensity = intensityMap[blastRadiusDepth] || 0.3;
      const glowLayers = 4;
      for (let i = glowLayers; i >= 1; i--) {
        const r = nodeRadius + i * 4;
        const gradient = ctx.createRadialGradient(x, y, nodeRadius, x, y, r);
        gradient.addColorStop(0, `rgba(249, 115, 22, ${intensity * (0.4 - i * 0.08)})`);
        gradient.addColorStop(1, 'rgba(249, 115, 22, 0)');
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = gradient;
        ctx.fill();
      }
      ctx.beginPath();
      ctx.arc(x, y, nodeRadius + 2, 0, 2 * Math.PI);
      ctx.strokeStyle = `rgba(249, 115, 22, ${intensity})`;
      ctx.lineWidth = 2 / globalScale;
      ctx.stroke();
    }

    // Glowing red border for malicious/suspicious nodes
    if (isThreat && !isInAttackPath && !isPathSource && !isPathTarget) {
      const glowLayers = 4;
      for (let i = glowLayers; i >= 1; i--) {
        const r = nodeRadius + i * 4;
        const gradient = ctx.createRadialGradient(x, y, nodeRadius, x, y, r);
        gradient.addColorStop(0, `rgba(239, 68, 68, ${0.4 - i * 0.08})`);
        gradient.addColorStop(1, 'rgba(239, 68, 68, 0)');
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = gradient;
        ctx.fill();
      }
      ctx.beginPath();
      ctx.arc(x, y, nodeRadius + 2, 0, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(239, 68, 68, 0.9)';
      ctx.lineWidth = 2 / globalScale;
      ctx.stroke();
    }

    // Search match highlight
    if (isSearchMatch && !isThreat) {
      ctx.beginPath();
      ctx.arc(x, y, nodeRadius + 2, 0, 2 * Math.PI);
      ctx.strokeStyle = '#38bdf8';
      ctx.lineWidth = 2 / globalScale;
      ctx.stroke();
    }

    // Risk propagation overlays
    if (riskLevel) {
      const riskGlowColors = {
        compromised: [239, 68, 68], // bright red - but pulsing fill is enough
        high: [249, 115, 22], // orange glow
        medium: [234, 179, 8], // yellow glow
        low: null // no glow for low risk
      };

      if (riskGlowColors[riskLevel]) {
        const [r, g, b] = riskGlowColors[riskLevel];
        const glowLayers = riskLevel === 'compromised' ? 8 : 6;
        const glowIntensity = riskLevel === 'compromised' ? 0.8 : 0.6;

        for (let i = glowLayers; i >= 1; i--) {
          const r_radius = nodeRadius + i * 4;
          const gradient = ctx.createRadialGradient(x, y, nodeRadius, x, y, r_radius);
          const alpha = glowIntensity - i * 0.08;
          gradient.addColorStop(0, `rgba(${r}, ${g}, ${b}, ${Math.max(0, alpha)})`);
          gradient.addColorStop(1, `rgba(${r}, ${g}, ${b}, 0)`);
          ctx.beginPath();
          ctx.arc(x, y, r_radius, 0, 2 * Math.PI);
          ctx.fillStyle = gradient;
          ctx.fill();
        }

        // Bright border for high contrast
        ctx.beginPath();
        ctx.arc(x, y, nodeRadius + 2, 0, 2 * Math.PI);
        ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, 1)`;
        ctx.lineWidth = 3 / globalScale;
        ctx.stroke();
      }
    }

    // Node fill
    ctx.beginPath();
    ctx.arc(x, y, nodeRadius, 0, 2 * Math.PI);
    ctx.fillStyle = nodeColor;
    ctx.fill();

    // Node border
    ctx.beginPath();
    ctx.arc(x, y, nodeRadius, 0, 2 * Math.PI);
    ctx.strokeStyle = isThreat ? 'rgba(239, 68, 68, 0.8)' : 'rgba(255,255,255,0.3)';
    ctx.lineWidth = 1 / globalScale;
    ctx.stroke();

    // Label
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillStyle = '#e5e7eb';
    ctx.fillText(label, x, y + nodeRadius + 2);

    ctx.restore();
  };

  return (
    <div className="threat-hunt-app">
      {/* Header */}
      <header className="app-header">
        <div className="header-content">
          <div className="header-title">
            <span className="header-icon">◉</span>
            <h1>Threat Hunting Graph</h1>
            <span className="status-dot"></span>
          </div>
          <p className="header-subtitle">Graph-based linkage of hosts, users, hashes and network indicators</p>
        </div>
        <button
          className="btn-primary"
          onClick={generateHypothesis}
          disabled={loadingAI}
        >
          {loadingAI ? (
            <>
              <span className="btn-spinner"></span>
              Analyzing...
            </>
          ) : (
            <>
              <span className="btn-icon">▸</span>
              AI Hypothesis
            </>
          )}
        </button>
        <button
          className="btn-secondary"
          onClick={simulateCompromise}
          disabled={!selectedNode || !blastRadiusData}
          style={{
            background: Object.keys(riskPropagation).length > 0 ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            color: '#fca5a5'
          }}
        >
          <span className="btn-icon">⚡</span>
          Simulate Compromise
        </button>
        {Object.keys(riskPropagation).length > 0 && (
          <button
            className="btn-secondary"
            onClick={resetSimulation}
            style={{
              background: 'rgba(156, 163, 175, 0.2)',
              border: '1px solid rgba(156, 163, 175, 0.4)',
              color: '#d1d5db'
            }}
          >
            <span className="btn-icon">🔄</span>
            Reset Simulation
          </button>
        )}
        <button
          className="btn-secondary"
          onClick={togglePathMode}
          style={{
            background: pathMode ? 'rgba(34, 197, 94, 0.2)' : 'transparent',
            border: pathMode ? '1px solid rgba(34, 197, 94, 0.4)' : '1px solid rgba(148, 163, 184, 0.3)',
            color: pathMode ? '#86efac' : '#e5e7eb'
          }}
        >
          <span className="btn-icon">🎯</span>
          Attack Path
        </button>
      </header>

      {/* View Tabs */}
      <div className="view-tabs" style={{ display: 'flex', padding: '0 1.5rem 0.75rem' }}>
        <button
          type="button"
          onClick={() => setActiveView('graph')}
          className={activeView === 'graph' ? 'tab-button active' : 'tab-button'}
          style={{
            padding: '0.4rem 0.9rem',
            borderRadius: '999px',
            border: '1px solid rgba(148, 163, 184, 0.4)',
            background: activeView === 'graph' ? 'rgba(34,197,94,0.16)' : 'transparent',
            color: '#e5e7eb',
            fontSize: '0.85rem',
            cursor: 'pointer'
          }}
        >
          Graph View
        </button>
        <button
          type="button"
          onClick={() => setActiveView('timeline')}
          className={activeView === 'timeline' ? 'tab-button active' : 'tab-button'}
          style={{
            padding: '0.4rem 0.9rem',
            borderRadius: '999px',
            border: '1px solid rgba(148, 163, 184, 0.4)',
            background: activeView === 'timeline' ? 'rgba(56,189,248,0.16)' : 'transparent',
            color: '#e5e7eb',
            fontSize: '0.85rem',
            cursor: 'pointer'
          }}
        >
          Timeline View
        </button>
        <button
          type="button"
          onClick={() => setActiveView('replay')}
          className={activeView === 'replay' ? 'tab-button active' : 'tab-button'}
          style={{
            padding: '0.4rem 0.9rem',
            borderRadius: '999px',
            border: '1px solid rgba(148, 163, 184, 0.4)',
            background: activeView === 'replay' ? 'rgba(139, 92, 246, 0.16)' : 'transparent',
            color: '#e5e7eb',
            fontSize: '0.85rem',
            cursor: 'pointer'
          }}
        >
          Attack Replay
        </button>
      </div>

      {apiError && (
        <div
          style={{
            margin: '0 1.5rem 0.75rem',
            padding: '0.5rem 0.85rem',
            borderRadius: '0.5rem',
            border: '1px solid rgba(239, 68, 68, 0.55)',
            background: 'rgba(127, 29, 29, 0.22)',
            color: '#fecaca',
            fontSize: '0.86rem'
          }}
        >
          {apiError}
        </div>
      )}

      {/* Attack Path Instruction Banner */}
      {pathMode && (
        <div
          style={{
            margin: '0 1.5rem 0.75rem',
            padding: '0.45rem 0.85rem',
            borderRadius: '0.5rem',
            border: '1px solid rgba(234, 179, 8, 0.6)',
            background:
              'linear-gradient(90deg, rgba(250, 204, 21, 0.18), rgba(15, 23, 42, 0.98))',
            color: '#facc15',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            boxShadow: '0 0 18px rgba(234, 179, 8, 0.35)'
          }}
        >
          <span style={{ fontSize: '0.9rem' }}>🎯</span>
          <span>
            {pathSource
              ? `✅ Source: ${pathSource.name || pathSource.id} — Now click target node`
              : '🎯 Path Mode Active — Click source node, then target node'}
          </span>
        </div>
      )}

      {/* AI Hypothesis Panel */}
      {hypothesis && (
        <div className="hypothesis-panel">
          <h3 className="panel-title">
            <span className="title-icon">◈</span>
            AI Threat Hypothesis
          </h3>
          <pre className="hypothesis-content">{hypothesis}</pre>
        </div>
      )}

      <div className="main-layout">
        {/* Left Sidebar - Filter Panel + Legend */}
        <aside className="sidebar sidebar-left">
          <div className="panel filter-panel">
            <h3 className="panel-title">Filter by Type</h3>
            <div className="filter-list">
              {NODE_TYPES.map(type => (
                <label key={type} className="filter-checkbox">
                  <input
                    type="checkbox"
                    checked={typeFilters[type]}
                    onChange={() => toggleTypeFilter(type)}
                  />
                  <span className="filter-color" style={{ background: NODE_COLORS[type] }}></span>
                  <span>{type} ({typeCounts[type] || 0})</span>
                </label>
              ))}
            </div>

            <div
              style={{
                marginTop: '0.75rem',
                paddingTop: '0.5rem',
                borderTop: '1px solid rgba(31,41,55,0.9)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.4rem'
              }}
            >
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  fontSize: '0.8rem',
                  color: '#e5e7eb'
                }}
              >
                <input
                  type="checkbox"
                  checked={threatOnly}
                  onChange={(e) => setThreatOnly(e.target.checked)}
                />
                <span style={{ color: '#f97373' }}>Show threats only</span>
              </label>

              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.25rem',
                  fontSize: '0.78rem'
                }}
              >
                <span style={{ color: '#9ca3af' }}>Relationship filter</span>
                <select
                  value={relFilter}
                  onChange={(e) => setRelFilter(e.target.value)}
                  style={{
                    backgroundColor: '#020617',
                    color: '#e5e7eb',
                    borderRadius: '0.25rem',
                    border: '1px solid rgba(55,65,81,0.9)',
                    padding: '0.25rem 0.4rem',
                    fontSize: '0.8rem'
                  }}
                >
                  <option value="ALL">All relationships</option>
                  <option value="LOGGED_INTO">LOGGED_INTO</option>
                  <option value="CONNECTED_TO">CONNECTED_TO</option>
                  <option value="RAN">RAN</option>
                </select>
              </div>
            </div>
          </div>

          <div className="panel legend-panel">
            <h3 className="panel-title">Legend</h3>
            {Object.entries(NODE_COLORS).map(([label, color]) => (
              <div key={label} className="legend-item">
                <div className="legend-dot" style={{ background: color }}></div>
                <span>{label}</span>
              </div>
            ))}
            <div className="legend-threat">
              <div className="legend-dot threat-glow"></div>
              <span>Malicious / Suspicious</span>
            </div>
            <h4 className="legend-subtitle">Relationships</h4>
            <div className="legend-relations">
              <span>→ LOGGED_INTO</span>
              <span>→ CONNECTED_TO</span>
              <span>→ RAN</span>
            </div>
          </div>
        </aside>

        {/* Center - Graph / Timeline / Replay */}
        <main className="graph-container">
          {activeView === 'graph' && (
            <>
              <div className="search-bar">
                <span className="search-icon">⌕</span>
                <input
                  type="text"
                  placeholder="Search node by name..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="search-input"
                />
                {searchQuery && (
                  <button
                    className="search-clear"
                    onClick={() => setSearchQuery('')}
                    aria-label="Clear search"
                  >
                    ×
                  </button>
                )}
                {searchQuery && (
                  <span className="search-results">
                    {searchMatches.size} match{searchMatches.size !== 1 ? 'es' : ''}
                  </span>
                )}
                <div style={{ marginLeft: 'auto' }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => {
                      if (fgRef.current) {
                        fgRef.current.zoomToFit(400, 50);
                      }
                    }}
                  >
                    <span className="btn-icon">⤢</span>
                    Fit Graph
                  </button>
                </div>
              </div>

              <div className="graph-wrapper">
                <ForceGraph2D
                  ref={fgRef}
                  graphData={filteredGraphData}
                  width={window.innerWidth}
                  height={window.innerHeight}
                  nodeRelSize={10}
                  nodeLabel={node => `${node.label}: ${node.name}`}
                  nodeCanvasObject={paintNode}
                  nodePointerAreaPaint={(node, color, ctx) => {
                    ctx.fillStyle = color;
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, 12, 0, 2 * Math.PI);
                    ctx.fill();
                  }}
                  linkLabel={link => link.type}
                  linkColor={(link) => {
                    const sourceId =
                      typeof link.source === 'object' ? link.source.id : link.source;
                    const targetId =
                      typeof link.target === 'object' ? link.target.id : link.target;
                    const srcIndex = attackPathIndexById.get(sourceId);
                    const tgtIndex = attackPathIndexById.get(targetId);
                    const isPathLink =
                      attackPath &&
                      attackPath.found &&
                      srcIndex !== undefined &&
                      tgtIndex !== undefined &&
                      Math.abs(srcIndex - tgtIndex) === 1;
                    return isPathLink
                      ? 'rgba(255, 220, 0, 0.9)'
                      : 'rgba(0, 212, 255, 0.25)';
                  }}
                  linkWidth={(link) => {
                    const sourceId =
                      typeof link.source === 'object' ? link.source.id : link.source;
                    const targetId =
                      typeof link.target === 'object' ? link.target.id : link.target;
                    const srcIndex = attackPathIndexById.get(sourceId);
                    const tgtIndex = attackPathIndexById.get(targetId);
                    const isPathLink =
                      attackPath &&
                      attackPath.found &&
                      srcIndex !== undefined &&
                      tgtIndex !== undefined &&
                      Math.abs(srcIndex - tgtIndex) === 1;
                    return isPathLink ? 4 : 1.5;
                  }}
                  linkDirectionalParticles={2}
                  linkDirectionalParticleSpeed={0.005}
                  linkDirectionalParticleColor={() => '00D4FF'}
                  d3AlphaDecay={0.01}
                  d3VelocityDecay={0.2}
                  cooldownTicks={200}
                  onEngineStop={() => {
                    if (!hasInitialFit.current && fgRef.current) {
                      fgRef.current.zoomToFit(400, 50);
                      hasInitialFit.current = true;
                    }
                  }}
                  linkDirectionalArrowLength={5}
                  linkDirectionalArrowRelPos={1}
                  onNodeClick={(node) => {
                    if (handlePathModeNodeClick(node)) return;
                    setSelectedNode(node);
                    axios.get(`${API_BASE_URL}/api/blast-radius/${node.id}`)
                      .then(res => {
                        setApiError('');
                        setBlastRadiusData(res.data);
                      })
                      .catch(err => {
                        console.error('Blast radius error:', err);
                        setApiError(`Unable to connect to API at ${API_BASE_URL}.`);
                      });
                  }}
                  backgroundColor="#0a0f14"
                />
              </div>
            </>
          )}

          {activeView === 'timeline' && (
            <div
              className="timeline-wrapper"
              style={{
                padding: '0.75rem 1.5rem 1rem',
                overflowY: 'auto',
                flex: 1,
                minHeight: 0,
                background: 'radial-gradient(circle at top, rgba(34,197,94,0.08), transparent 55%)',
                position: 'relative'
              }}
            >
              {/* Vertical timeline spine */}
              <div
                style={{
                  position: 'absolute',
                  left: '1.25rem',
                  top: '2.4rem',
                  bottom: '1.2rem',
                  width: '2px',
                  background: 'linear-gradient(to bottom, rgba(148,163,184,0.7), rgba(15,23,42,0.1))',
                  pointerEvents: 'none'
                }}
              />
              <h3
                style={{
                  color: '#e5e7eb',
                  fontSize: '0.9rem',
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  marginBottom: '0.75rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  flexShrink: 0
                }}
              >
                <span style={{ fontSize: '0.75rem', color: '#38bdf8' }}>▮</span>
                Activity Timeline
              </h3>

              {/* Summary bar */}
              <div
                style={{
                  display: 'flex',
                  gap: '0.75rem',
                  marginBottom: '0.9rem',
                  fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace',
                  flexShrink: 0
                }}
              >
                <div
                  style={{
                    flex: 1,
                    padding: '0.4rem 0.7rem',
                    borderRadius: '0.4rem',
                    background: 'linear-gradient(90deg, rgba(148,163,184,0.2), rgba(15,23,42,0.9))',
                    border: '1px solid rgba(148,163,184,0.4)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.1rem'
                  }}
                >
                  <span style={{ fontSize: '0.7rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Total Events
                  </span>
                  <span style={{ fontSize: '0.95rem', color: '#e5e7eb' }}>{timelineSummary.total}</span>
                </div>
                <div
                  style={{
                    flex: 1,
                    padding: '0.4rem 0.7rem',
                    borderRadius: '0.4rem',
                    background: 'linear-gradient(90deg, rgba(248,113,113,0.20), rgba(15,23,42,0.95))',
                    border: '1px solid rgba(248,113,113,0.6)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.1rem'
                  }}
                >
                  <span style={{ fontSize: '0.7rem', color: '#fecaca', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Malicious
                  </span>
                  <span style={{ fontSize: '0.95rem', color: '#fee2e2' }}>{timelineSummary.malicious}</span>
                </div>
                <div
                  style={{
                    flex: 1,
                    padding: '0.4rem 0.7rem',
                    borderRadius: '0.4rem',
                    background: 'linear-gradient(90deg, rgba(248,250,252,0.04), rgba(15,23,42,0.95))',
                    border: '1px solid rgba(56,189,248,0.5)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.1rem'
                  }}
                >
                  <span style={{ fontSize: '0.7rem', color: '#7dd3fc', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Suspicious
                  </span>
                  <span style={{ fontSize: '0.95rem', color: '#e0f2fe' }}>{timelineSummary.suspicious}</span>
                </div>
              </div>

              <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
                {(() => {
                  let lastDateKey = null;
                  return timelineItems.map(node => {
                    const isThreat = isMaliciousOrSuspicious(node);
                    const ts = node.timestamp;
                    const displayTime = formatTimestamp(ts);
                    const typeColor = NODE_COLORS[node.label] || '#6b7280';

                    let dateKey = 'unknown';
                    let dateLabel = 'Unknown Date';
                    if (ts) {
                      const d = new Date(ts);
                      if (Number.isFinite(d.getTime())) {
                        dateKey = d.toISOString().slice(0, 10);
                        dateLabel = d.toLocaleDateString('en-US', {
                          month: 'short',
                          day: '2-digit',
                          year: 'numeric'
                        });
                      }
                    }
                    const showDateHeader = dateKey !== lastDateKey;
                    lastDateKey = dateKey;

                    const baseBg = 'rgba(15,23,42,0.96)';
                    const threatBg = 'linear-gradient(90deg, rgba(248,113,113,0.22), rgba(15,23,42,0.98))';

                    return (
                      <React.Fragment key={node.id}>
                        {showDateHeader && (
                          <div
                            style={{
                              margin: '0.75rem 0 0.35rem',
                              fontSize: '0.75rem',
                              color: '#9ca3af',
                              textTransform: 'uppercase',
                              letterSpacing: '0.12em'
                            }}
                          >
                            {dateLabel}
                          </div>
                        )}
                        <div
                          className="timeline-item"
                          style={{
                            position: 'relative',
                            marginLeft: '1.4rem',
                            borderLeft: `2px solid ${isThreat ? '#ef4444' : 'rgba(31,41,55,0.9)'}`,
                            background: isThreat ? threatBg : baseBg,
                            padding: '0.55rem 0.9rem 0.6rem 1.0rem',
                            marginBottom: '0.55rem',
                            boxShadow: isThreat
                              ? '0 0 0 1px rgba(15,23,42,0.9), 0 0 24px rgba(248,113,113,0.55)'
                              : '0 0 0 1px rgba(15,23,42,0.9), 0 8px 16px rgba(0,0,0,0.35)',
                            borderRadius: '0.4rem',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '0.25rem'
                          }}
                        >
                          {/* type-colored dot on the timeline spine */}
                          <span
                            style={{
                              position: 'absolute',
                              left: '-1.25rem',
                              top: '0.85rem',
                              width: '10px',
                              height: '10px',
                              borderRadius: '999px',
                              backgroundColor: typeColor,
                              boxShadow: isThreat
                                ? '0 0 10px rgba(248,113,113,0.95)'
                                : '0 0 8px rgba(148,163,184,0.8)',
                              border: '2px solid #020617'
                            }}
                          />
                          <div
                            className="timeline-header"
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                              gap: '0.5rem'
                            }}
                          >
                            <span
                              style={{
                                fontFamily:
                                  'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace',
                                fontSize: '0.75rem',
                                color: '#9ca3af'
                              }}
                            >
                              {displayTime}
                            </span>
                            <span
                              style={{
                                backgroundColor: typeColor,
                                color: '#020617',
                                fontSize: '0.7rem',
                                fontWeight: 600,
                                padding: '0.15rem 0.45rem',
                                borderRadius: '999px',
                                textTransform: 'uppercase',
                                letterSpacing: '0.06em'
                              }}
                            >
                              {node.label || 'Unknown'}
                            </span>
                          </div>

                          <div
                            className="timeline-body"
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'flex-end',
                              gap: '0.75rem'
                            }}
                          >
                            <div>
                              <div
                                style={{
                                  color: '#e5e7eb',
                                  fontSize: '0.9rem',
                                  fontWeight: 500
                                }}
                              >
                                {node.name || node.id}
                              </div>
                              <div
                                style={{
                                  marginTop: '0.1rem',
                                  fontSize: '0.75rem',
                                  color: isThreat ? '#fecaca' : '#6b7280'
                                }}
                              >
                                {isThreat ? 'Malicious / Suspicious activity' : 'Benign / expected activity'}
                              </div>
                            </div>

                            <div
                              style={{
                                display: 'flex',
                                flexDirection: 'column',
                                alignItems: 'flex-end',
                                gap: '0.15rem'
                              }}
                            >
                              {node.malicious !== undefined && (
                                <span
                                  style={{
                                    fontSize: '0.7rem',
                                    color: node.malicious ? '#fecaca' : '#22c55e'
                                  }}
                                >
                                  {node.malicious ? 'Malicious' : 'Not malicious'}
                                </span>
                              )}
                              {node.suspicious !== undefined && (
                                <span
                                  style={{
                                    fontSize: '0.7rem',
                                    color: node.suspicious ? '#fecaca' : '#22c55e'
                                  }}
                                >
                                  {node.suspicious ? 'Suspicious' : 'Not suspicious'}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </React.Fragment>
                    );
                  });
                })()}
              </div>

              {timelineItems.length === 0 && (
                <div
                  style={{
                    marginTop: '1rem',
                    fontSize: '0.85rem',
                    color: '#6b7280',
                    fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace'
                  }}
                >
                  No activity available. Load seed data or adjust your graph filters.
                </div>
              )}
            </div>
          )}

          {activeView === 'replay' && (
            <div
              className="replay-wrapper"
              style={{
                padding: '0.75rem 1.5rem 1rem',
                height: '100%',
                background: 'radial-gradient(circle at top, rgba(139, 92, 246, 0.08), transparent 55%)',
                position: 'relative',
                display: 'flex',
                flexDirection: 'column'
              }}
            >
              {/* Stats bar */}
              <div
                style={{
                  display: 'flex',
                  gap: '0.75rem',
                  marginBottom: '1rem',
                  fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, Liberation Mono, Courier New, monospace'
                }}
              >
                <div
                  style={{
                    flex: 1,
                    padding: '0.4rem 0.7rem',
                    borderRadius: '0.4rem',
                    background: 'linear-gradient(90deg, rgba(139, 92, 246, 0.2), rgba(15,23,42,0.9))',
                    border: '1px solid rgba(139, 92, 246, 0.4)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.1rem'
                  }}
                >
                  <span style={{ fontSize: '0.7rem', color: '#c4b5fd', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Current Time
                  </span>
                  <span style={{ fontSize: '0.85rem', color: '#e9d5ff' }}>{replayStats.currentTimestamp}</span>
                </div>
                <div
                  style={{
                    flex: 1,
                    padding: '0.4rem 0.7rem',
                    borderRadius: '0.4rem',
                    background: 'linear-gradient(90deg, rgba(6, 182, 212, 0.2), rgba(15,23,42,0.9))',
                    border: '1px solid rgba(6, 182, 212, 0.4)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.1rem'
                  }}
                >
                  <span style={{ fontSize: '0.7rem', color: '#67e8f9', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Nodes Visible
                  </span>
                  <span style={{ fontSize: '0.95rem', color: '#cffafe' }}>{replayStats.visibleCount}</span>
                </div>
                <div
                  style={{
                    flex: 2,
                    padding: '0.4rem 0.7rem',
                    borderRadius: '0.4rem',
                    background: 'linear-gradient(90deg, rgba(148,163,184,0.2), rgba(15,23,42,0.9))',
                    border: '1px solid rgba(148,163,184, 0.4)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.1rem'
                  }}
                >
                  <span style={{ fontSize: '0.7rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Attack Morphology
                  </span>
                  <svg width="100%" height="30" style={{ marginTop: '0.2rem' }}>
                    <polyline
                      fill="none"
                      stroke="#06b6d4"
                      strokeWidth="2"
                      points={replayStats.curveData.map(point => `${point.x * 100}%,${(1 - point.y) * 20 + 5}`).join(' ')}
                    />
                  </svg>
                </div>
              </div>

              {/* Graph */}
              <div
                ref={replayContainerRef}
                className="graph-wrapper"
                style={{
                  flex: 1,
                  minHeight: 300,
                  position: 'relative',
                  display: 'flex',
                  alignItems: 'stretch',
                  overflow: 'hidden'
                }}
              >
                {replayContainerSize.width > 0 && replayContainerSize.height > 0 && (
                  <ForceGraph2D
                    ref={fgRef}
                    graphData={{ nodes: [...replayGraphData.nodes], links: [...replayGraphData.links] }}
                    width={replayContainerSize.width}
                    height={replayContainerSize.height}
                    nodeRelSize={10}
                    nodeLabel={node => `${node.label}: ${node.name}`}
                    nodeCanvasObject={(node, ctx, globalScale) => {
                      const x = node.x;
                      const y = node.y;
                      const nodeRadius = 6;

                      if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(globalScale)) {
                        return;
                      }

                      const label = node.name || node.id;
                      const fontSize = 12 / globalScale;
                      ctx.font = `${fontSize}px JetBrains Mono, Fira Code, Consolas, monospace`;

                      // Check if this is one of the last 3 nodes (recent additions)
                      const nodeIndex = replayGraphData.nodes.findIndex(n => n.id === node.id);
                      const isRecent = nodeIndex >= replayGraphData.nodes.length - 3;

                      const baseColor = NODE_COLORS[node.label] || '#6b7280';
                      const nodeColor = isRecent ? '#06b6d4' : baseColor; // Cyan for recent nodes

                      ctx.save();

                      ctx.beginPath();
                      ctx.arc(x, y, nodeRadius, 0, 2 * Math.PI);
                      ctx.fillStyle = nodeColor;
                      ctx.fill();

                      ctx.beginPath();
                      ctx.arc(x, y, nodeRadius, 0, 2 * Math.PI);
                      ctx.strokeStyle = isRecent ? 'rgba(6, 182, 212, 0.8)' : 'rgba(255,255,255,0.3)';
                      ctx.lineWidth = 1 / globalScale;
                      ctx.stroke();

                      // Glow for recent nodes
                      if (isRecent) {
                        const glowLayers = 3;
                        for (let i = glowLayers; i >= 1; i--) {
                          const r = nodeRadius + i * 3;
                          const gradient = ctx.createRadialGradient(x, y, nodeRadius, x, y, r);
                          const alpha = 0.4 - i * 0.1;
                          gradient.addColorStop(0, `rgba(6, 182, 212, ${Math.max(0, alpha)})`);
                          gradient.addColorStop(1, 'rgba(6, 182, 212, 0)');
                          ctx.beginPath();
                          ctx.arc(x, y, r, 0, 2 * Math.PI);
                          ctx.fillStyle = gradient;
                          ctx.fill();
                        }
                      }

                      ctx.textAlign = 'center';
                      ctx.textBaseline = 'top';
                      ctx.fillStyle = '#e5e7eb';
                      ctx.fillText(label, x, y + nodeRadius + 2);

                      ctx.restore();
                    }}
                    nodePointerAreaPaint={(node, color, ctx) => {
                      ctx.fillStyle = color;
                      ctx.beginPath();
                      ctx.arc(node.x, node.y, 12, 0, 2 * Math.PI);
                      ctx.fill();
                    }}
                    linkLabel={link => link.type}
                    linkColor={(link) => {
                      const sourceId =
                        typeof link.source === 'object' ? link.source.id : link.source;
                      const targetId =
                        typeof link.target === 'object' ? link.target.id : link.target;
                      const srcIndex = attackPathIndexById.get(sourceId);
                      const tgtIndex = attackPathIndexById.get(targetId);
                      const isPathLink =
                        attackPath &&
                        attackPath.found &&
                        srcIndex !== undefined &&
                        tgtIndex !== undefined &&
                        Math.abs(srcIndex - tgtIndex) === 1;
                      return isPathLink
                        ? 'rgba(255, 220, 0, 0.9)'
                        : 'rgba(0, 212, 255, 0.25)';
                    }}
                    linkWidth={(link) => {
                      const sourceId =
                        typeof link.source === 'object' ? link.source.id : link.source;
                      const targetId =
                        typeof link.target === 'object' ? link.target.id : link.target;
                      const srcIndex = attackPathIndexById.get(sourceId);
                      const tgtIndex = attackPathIndexById.get(targetId);
                      const isPathLink =
                        attackPath &&
                        attackPath.found &&
                        srcIndex !== undefined &&
                        tgtIndex !== undefined &&
                        Math.abs(srcIndex - tgtIndex) === 1;
                      return isPathLink ? 4 : 1.5;
                    }}
                    linkDirectionalParticles={2}
                    linkDirectionalParticleSpeed={0.005}
                    linkDirectionalParticleColor={() => '00D4FF'}
                    d3AlphaDecay={0.01}
                    d3VelocityDecay={0.2}
                    cooldownTicks={200}
                    onEngineStop={() => {
                      if (!hasInitialFit.current && fgRef.current) {
                        fgRef.current.zoomToFit(400, 50);
                        hasInitialFit.current = true;
                      }
                    }}
                    linkDirectionalArrowLength={5}
                    linkDirectionalArrowRelPos={1}
                    backgroundColor="#0a0f14"
                  />
                )}
              </div>

              {/* Controls */}
              <div
                style={{
                  display: 'flex',
                  gap: '0.75rem',
                  alignItems: 'center',
                  marginTop: '1rem',
                  padding: '0.75rem',
                  background: 'rgba(15, 23, 42, 0.8)',
                  borderRadius: '0.5rem',
                  border: '1px solid rgba(148, 163, 184, 0.2)'
                }}
              >
                <button
                  onClick={resetReplay}
                  style={{
                    padding: '0.5rem 1rem',
                    background: 'rgba(156, 163, 175, 0.2)',
                    border: '1px solid rgba(156, 163, 175, 0.4)',
                    borderRadius: '0.375rem',
                    color: '#d1d5db',
                    cursor: 'pointer',
                    fontSize: '0.875rem'
                  }}
                >
                  ⏮ Reset
                </button>
                <button
                  onClick={isPlaying ? pauseReplay : startReplay}
                  style={{
                    padding: '0.5rem 1rem',
                    background: isPlaying ? 'rgba(239, 68, 68, 0.2)' : 'rgba(34, 197, 94, 0.2)',
                    border: `1px solid ${isPlaying ? 'rgba(239, 68, 68, 0.4)' : 'rgba(34, 197, 94, 0.4)'}`,
                    borderRadius: '0.375rem',
                    color: isPlaying ? '#fca5a5' : '#86efac',
                    cursor: 'pointer',
                    fontSize: '0.875rem'
                  }}
                >
                  {isPlaying ? '⏸ Pause' : '▶ Play'}
                </button>
                <div style={{ flex: 1, marginLeft: '1rem' }}>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={replayProgress * 100}
                    onChange={(e) => setReplayProgress(parseFloat(e.target.value) / 100)}
                    style={{
                      width: '100%',
                      height: '6px',
                      borderRadius: '3px',
                      background: 'rgba(148, 163, 184, 0.3)',
                      outline: 'none'
                    }}
                  />
                </div>
                <span style={{ fontSize: '0.875rem', color: '#9ca3af', minWidth: '3rem' }}>
                  {Math.round(replayProgress * 100)}%
                </span>
              </div>
            </div>
          )}
        </main>

        {/* Right Sidebar - Node Details & Attack Path */}
        {(selectedNode || (attackPath && attackPath.found)) && (
          <aside className="sidebar sidebar-right">
            {selectedNode && (
              <div className="panel details-panel">
                <div className="panel-header">
                  <h3 className="panel-title">Node Details</h3>
                  <button
                    className="btn-close"
                    onClick={() => setSelectedNode(null)}
                    aria-label="Close"
                  >
                    ×
                  </button>
                </div>
                <div className={`details-content ${isMaliciousOrSuspicious(selectedNode) ? 'threat-node' : ''}`}>
                  {Object.entries(selectedNode)
                    .filter(([k]) => !['x', 'y', 'vx', 'vy', 'index', '__indexColor'].includes(k))
                    .map(([key, value]) => (
                      <div key={key} className="detail-row">
                        <span className="detail-key">{key}</span>
                        <span className={`detail-value ${key === 'malicious' || key === 'suspicious' ? (value ? 'threat' : 'safe') : ''}`}>
                          {String(value)}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            )}
            {blastRadiusData && (
              <div className="panel blast-radius-panel">
                <div className="panel-header">
                  <h3 className="panel-title">Blast Radius</h3>
                  <button
                    className="btn-close"
                    onClick={() => setBlastRadiusData(null)}
                    aria-label="Clear"
                  >
                    ×
                  </button>
                </div>
                <div className="blast-radius-content">
                  <div className="blast-radius-total">
                    <div className="blast-radius-number">{blastRadiusData.total_count}</div>
                    <div className="blast-radius-label">Reachable Assets</div>
                  </div>
                  <div className="blast-radius-breakdown">
                    <h4 style={{ marginBottom: '0.5rem', fontSize: '0.85rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em' }}>By Type</h4>
                    {Object.entries(blastRadiusData.label_counts).map(([type, count]) => (
                      <div key={type} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.35rem 0', fontSize: '0.85rem', color: '#e5e7eb' }}>
                        <span>{type}:</span>
                        <span style={{ color: NODE_COLORS[type] || '#6b7280', fontWeight: 'bold' }}>{count}</span>
                      </div>
                    ))}
                  </div>
                  <div className="blast-radius-warning" style={{ marginTop: '0.75rem', padding: '0.6rem', backgroundColor: 'rgba(249, 115, 22, 0.15)', border: '1px solid rgba(249, 115, 22, 0.4)', borderRadius: '0.4rem', fontSize: '0.8rem', color: '#fed7aa' }}>
                    ⚠️ Compromising this node exposes <strong>{blastRadiusData.total_count}</strong> asset{blastRadiusData.total_count !== 1 ? 's' : ''}
                  </div>
                </div>
              </div>
            )}
            {attackPath && attackPath.found && (
              <div className="panel" style={{ marginTop: '0.75rem' }}>
                <div className="panel-header">
                  <h3
                    className="panel-title"
                    style={{ color: '#facc15', textShadow: '0 0 10px rgba(250, 204, 21, 0.7)' }}
                  >
                    ✅ Attack Path Found
                  </h3>
                  <button
                    className="btn-close"
                    onClick={() => {
                      setAttackPath(null);
                      setPathSource(null);
                      setPathTarget(null);
                    }}
                    aria-label="Clear Path"
                  >
                    ×
                  </button>
                </div>
                <div style={{ paddingTop: '0.25rem' }}>
                  <div
                    style={{
                      fontSize: '1.4rem',
                      fontWeight: 600,
                      color: '#e5e7eb',
                      marginBottom: '0.5rem'
                    }}
                  >
                    {attackPath.hops} hops
                  </div>
                  <div
                    style={{
                      fontSize: '0.85rem',
                      color: '#e5e7eb',
                      marginBottom: '0.75rem',
                      lineHeight: 1.5
                    }}
                  >
                    {(attackPath.path_nodes || []).map((id, idx) => {
                      const node = graphData.nodes.find(n => n.id === id);
                      const name = node?.name || node?.id || id;
                      return (
                        <React.Fragment key={id}>
                          {idx > 0 && ' \u2192 '}
                          {name}
                        </React.Fragment>
                      );
                    })}
                  </div>
                  <button
                    className="btn-secondary"
                    onClick={() => {
                      setAttackPath(null);
                      setPathSource(null);
                      setPathTarget(null);
                    }}
                    style={{
                      width: '100%',
                      justifyContent: 'center',
                      padding: '0.45rem 0.75rem',
                      borderRadius: '0.4rem',
                      border: '1px solid rgba(148, 163, 184, 0.6)',
                      background: 'rgba(15, 23, 42, 0.85)',
                      color: '#e5e7eb',
                      cursor: 'pointer',
                      fontSize: '0.8rem'
                    }}
                  >
                    Clear Path
                  </button>
                </div>
              </div>
            )}
            {attackPath && !attackPath.found && (pathSource || pathTarget) && (
              <div
                className="panel"
                style={{
                  marginTop: '0.75rem',
                  borderColor: 'rgba(248, 113, 113, 0.6)',
                  boxShadow: '0 0 16px rgba(248, 113, 113, 0.35)',
                  background:
                    'linear-gradient(90deg, rgba(30, 64, 175, 0.7), rgba(15, 23, 42, 0.98))'
                }}
              >
                <div className="panel-header">
                  <h3
                    className="panel-title"
                    style={{ color: '#fecaca', textShadow: '0 0 10px rgba(248, 113, 113, 0.7)' }}
                  >
                    ⚠️ No Attack Path Found
                  </h3>
                  <button
                    className="btn-close"
                    onClick={() => {
                      setAttackPath(null);
                      setPathSource(null);
                      setPathTarget(null);
                    }}
                    aria-label="Clear Path"
                  >
                    ×
                  </button>
                </div>
                <div style={{ paddingTop: '0.25rem', fontSize: '0.8rem', color: '#e5e7eb' }}>
                  <div style={{ marginBottom: '0.4rem' }}>
                    No valid attack path exists between:
                  </div>
                  <div style={{ fontWeight: 500 }}>
                    <span style={{ color: '#bfdbfe' }}>
                      {pathSource ? pathSource.name || pathSource.id : 'Source'}
                    </span>
                    <span style={{ color: '#9ca3af' }}> \u2192 </span>
                    <span style={{ color: '#fecaca' }}>
                      {pathTarget ? pathTarget.name || pathTarget.id : 'Target'}
                    </span>
                  </div>
                  <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#9ca3af' }}>
                    Adjust your selection or graph filters and try again.
                  </div>
                </div>
              </div>
            )}
          </aside>
        )}
      </div>
    </div>
  );
}
