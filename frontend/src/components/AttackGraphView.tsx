import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Server, Terminal, Radio, AlertTriangle, X, ZoomIn, ZoomOut, RotateCcw } from 'lucide-react';
import type { AlertIncident } from '../types/soc';
import { sound } from '../utils/audio';

interface AttackGraphViewProps {
  alerts: AlertIncident[];
  onSelectAlert?: (alert: AlertIncident) => void;
}

interface Node {
  id: string;
  label: string;
  type: 'host' | 'process' | 'mitre' | 'c2';
  severity: string;
  risk: number;
  alertRef?: AlertIncident;
  x: number;
  y: number;
}

interface Edge {
  source: string;
  target: string;
  label: string;
  severity: string;
}

export const AttackGraphView: React.FC<AttackGraphViewProps> = ({ alerts, onSelectAlert }) => {
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [zoom, setZoom] = useState(1);

  // Derive nodes and edges from correlated alerts
  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, Node>();
    const edgeList: Edge[] = [];

    // Columns: Hosts (x=120) -> Processes (x=380) -> MITRE (x=640) -> C2 (x=900)
    const hostList = Array.from(new Set(alerts.map(a => a.host)));
    const procList = Array.from(new Set(alerts.map(a => a.process_image ? a.process_image.split('\\').pop()?.split('/').pop() || 'process' : 'process')));
    const mitreList = Array.from(new Set(alerts.map(a => a.mitre_id || 'T1027')));
    const c2List = Array.from(new Set(alerts.map(a => a.dest_ip).filter(Boolean)));

    // Create Host nodes
    hostList.forEach((h, idx) => {
      const topAlert = alerts.find(a => a.host === h);
      const y = 80 + idx * (360 / Math.max(hostList.length, 1));
      nodeMap.set(`host-${h}`, {
        id: `host-${h}`,
        label: h,
        type: 'host',
        severity: topAlert?.severity || 'MEDIUM',
        risk: topAlert?.risk_score || 50,
        alertRef: topAlert,
        x: 120,
        y: y
      });
    });

    // Create Process nodes
    procList.forEach((p, idx) => {
      const topAlert = alerts.find(a => (a.process_image || '').includes(p));
      const y = 60 + idx * (400 / Math.max(procList.length, 1));
      nodeMap.set(`proc-${p}`, {
        id: `proc-${p}`,
        label: p,
        type: 'process',
        severity: topAlert?.severity || 'HIGH',
        risk: topAlert?.risk_score || 70,
        alertRef: topAlert,
        x: 380,
        y: y
      });
    });

    // Create MITRE nodes
    mitreList.forEach((m, idx) => {
      const topAlert = alerts.find(a => a.mitre_id === m);
      const y = 80 + idx * (360 / Math.max(mitreList.length, 1));
      nodeMap.set(`mitre-${m}`, {
        id: `mitre-${m}`,
        label: `${m} ${topAlert?.mitre_name ? `(${topAlert.mitre_name.split(' ')[0]})` : ''}`,
        type: 'mitre',
        severity: topAlert?.severity || 'HIGH',
        risk: topAlert?.risk_score || 80,
        alertRef: topAlert,
        x: 640,
        y: y
      });
    });

    // Create C2 nodes
    c2List.forEach((c, idx) => {
      const topAlert = alerts.find(a => a.dest_ip === c);
      const y = 100 + idx * (320 / Math.max(c2List.length, 1));
      nodeMap.set(`c2-${c}`, {
        id: `c2-${c}`,
        label: c,
        type: 'c2',
        severity: 'CRITICAL',
        risk: 92,
        alertRef: topAlert,
        x: 900,
        y: y
      });
    });

    // Connect edges based on alerts
    alerts.forEach(a => {
      const hId = `host-${a.host}`;
      const procName = a.process_image ? a.process_image.split('\\').pop()?.split('/').pop() || 'process' : 'process';
      const pId = `proc-${procName}`;
      const mId = `mitre-${a.mitre_id || 'T1027'}`;
      const cId = a.dest_ip ? `c2-${a.dest_ip}` : null;

      // Host -> Process
      if (nodeMap.has(hId) && nodeMap.has(pId)) {
        edgeList.push({ source: hId, target: pId, label: 'executes', severity: a.severity });
      }
      // Process -> MITRE
      if (nodeMap.has(pId) && nodeMap.has(mId)) {
        edgeList.push({ source: pId, target: mId, label: 'exhibits', severity: a.severity });
      }
      // MITRE -> C2
      if (cId && nodeMap.has(mId) && nodeMap.has(cId)) {
        edgeList.push({ source: mId, target: cId, label: 'beacons to', severity: a.severity });
      }
    });

    return { nodes: Array.from(nodeMap.values()), edges: edgeList };
  }, [alerts]);

  const getNodeColor = (type: string, severity: string) => {
    if (type === 'c2') return '#F43F5E'; // Berry Rose for C2
    if (severity === 'CRITICAL') return '#F43F5E';
    if (severity === 'HIGH') return '#F59E0B';
    if (severity === 'MEDIUM') return '#818CF8';
    return '#10B981';
  };

  const handleNodeClick = (node: Node) => {
    sound.playTick();
    setSelectedNode(node);
    if (node.alertRef && onSelectAlert) {
      onSelectAlert(node.alertRef);
    }
  };

  return (
    <div className="relative w-full h-[540px] bg-[#0A0912] rounded-xl border border-white/10 overflow-hidden select-none">
      {/* Graph Toolbar */}
      <div className="absolute top-3 left-4 z-10 flex items-center space-x-2">
        <span className="text-xs font-mono px-3 py-1 rounded-full bg-white/5 border border-white/10 text-violet-300 backdrop-blur-md">
          Provenance Causality Graph · {nodes.length} Nodes · {edges.length} Links
        </span>
      </div>

      <div className="absolute top-3 right-4 z-10 flex items-center space-x-1.5 bg-[#12111E]/95 p-1 rounded-xl border border-white/10 backdrop-blur-md">
        <button
          onClick={() => setZoom(z => Math.min(z + 0.15, 1.6))}
          className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/5"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom(z => Math.max(z - 0.15, 0.7))}
          className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/5"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom(1)}
          className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-white/5"
          title="Reset View"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* SVG Canvas */}
      <svg
        className="w-full h-full cursor-grab active:cursor-grabbing transition-transform duration-200"
        style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
        viewBox="0 0 1020 520"
      >
        <defs>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3.5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Column Group Labels */}
        <text x="120" y="30" textAnchor="middle" fill="#6366F1" fontSize="11" fontFamily="JetBrains Mono" fontWeight="bold">HOST ASSETS</text>
        <text x="380" y="30" textAnchor="middle" fill="#818CF8" fontSize="11" fontFamily="JetBrains Mono" fontWeight="bold">PROCESS EXECUTION</text>
        <text x="640" y="30" textAnchor="middle" fill="#A855F7" fontSize="11" fontFamily="JetBrains Mono" fontWeight="bold">MITRE TECHNIQUE</text>
        <text x="900" y="30" textAnchor="middle" fill="#F43F5E" fontSize="11" fontFamily="JetBrains Mono" fontWeight="bold">C2 DESTINATION</text>

        {/* Connecting Edges */}
        {edges.map((edge, idx) => {
          const s = nodes.find(n => n.id === edge.source);
          const t = nodes.find(n => n.id === edge.target);
          if (!s || !t) return null;

          const isHighlighted = selectedNode && (selectedNode.id === s.id || selectedNode.id === t.id);
          const dx = t.x - s.x;
          const cx1 = s.x + dx * 0.5;
          const cx2 = t.x - dx * 0.5;
          const pathD = `M ${s.x} ${s.y} C ${cx1} ${s.y}, ${cx2} ${t.y}, ${t.x} ${t.y}`;

          return (
            <g key={idx}>
              <path
                d={pathD}
                fill="none"
                stroke={isHighlighted ? '#818CF8' : 'rgba(255,255,255,0.12)'}
                strokeWidth={isHighlighted ? 2.5 : 1.2}
                strokeDasharray={edge.severity === 'CRITICAL' ? '4 3' : 'none'}
              />
              {/* Animated particle pulse for Critical edges */}
              {edge.severity === 'CRITICAL' && (
                <circle r="2.5" fill="#F43F5E" filter="url(#glow)">
                  <animateMotion path={pathD} dur="2.5s" repeatCount="indefinite" />
                </circle>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map(node => {
          const color = getNodeColor(node.type, node.severity);
          const isSelected = selectedNode?.id === node.id;

          return (
            <g
              key={node.id}
              onClick={() => handleNodeClick(node)}
              className="cursor-pointer transition-transform"
            >
              {/* Outer Glow Halo */}
              <circle
                cx={node.x}
                cy={node.y}
                r={isSelected ? 22 : 16}
                fill={color}
                fillOpacity={isSelected ? 0.3 : 0.15}
                stroke={color}
                strokeWidth={isSelected ? 2 : 1}
                strokeDasharray={isSelected ? '3 3' : 'none'}
                filter="url(#glow)"
              />
              {/* Inner Node Core */}
              <circle
                cx={node.x}
                cy={node.y}
                r={node.type === 'c2' || node.severity === 'CRITICAL' ? 8 : 6}
                fill={color}
              />
              {/* Node Label */}
              <text
                x={node.x}
                y={node.y + 24}
                textAnchor="middle"
                fill={isSelected ? '#FFFFFF' : '#E9D5FF'}
                fontSize="10"
                fontFamily="Space Grotesk, sans-serif"
                fontWeight={isSelected ? 'bold' : 'normal'}
              >
                {node.label}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Selected Node Inspector Drawer / Card */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            className="absolute right-4 bottom-4 w-72 bg-[#12111F]/98 backdrop-blur-xl border border-white/15 rounded-2xl p-4 shadow-2xl z-20 text-xs"
          >
            <div className="flex items-center justify-between pb-2 border-b border-white/10">
              <span className="font-mono text-[10px] text-violet-300 uppercase tracking-wider">
                {selectedNode.type.toUpperCase()} NODE
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-zinc-400 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="mt-2.5 space-y-2">
              <h5 className="font-bold text-white text-sm break-all">{selectedNode.label}</h5>
              <div className="flex items-center space-x-2">
                <span className="text-zinc-400">Risk Score:</span>
                <span className="font-mono font-bold text-rose-400">{selectedNode.risk}/100</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-500/20 text-rose-300 font-mono">
                  {selectedNode.severity}
                </span>
              </div>
              {selectedNode.alertRef && (
                <div className="pt-2 border-t border-white/5 text-[11px] text-zinc-300">
                  <p className="text-zinc-400">Linked Incident:</p>
                  <p className="font-mono text-violet-300 font-semibold">{selectedNode.alertRef.alert_id}</p>
                  <p className="line-clamp-2 mt-0.5">{selectedNode.alertRef.detection_title}</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
