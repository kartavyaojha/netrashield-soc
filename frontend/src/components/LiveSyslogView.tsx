import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Square, Flame, Trash2, Wifi, WifiOff, Tv } from 'lucide-react';
import { sound } from '../utils/audio';

interface LiveSyslogViewProps {
  apiBaseUrl?: string;
}

export const LiveSyslogView: React.FC<LiveSyslogViewProps> = () => {
  const [logs, setLogs] = useState<string[]>([]);
  const [isListening, setIsListening] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState('');
  const [crtMode, setCrtMode] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Connect WebSocket
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.port === '5173'
      ? `${window.location.hostname}:8000`
      : window.location.host;
    const wsUrl = `${protocol}//${host}/ws/syslog`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      setLogs(prev => [...prev, `[INFO] Connected to NetraShield WebSocket Syslog Stream (${wsUrl})`]);
    };

    ws.onmessage = (event) => {
      setLogs(prev => [...prev, event.data]);
    };

    ws.onclose = () => {
      setWsConnected(false);
      setLogs(prev => [...prev, `[WARN] WebSocket Syslog Stream disconnected.`]);
    };

    ws.onerror = () => {
      setWsConnected(false);
    };

    return () => {
      ws.close();
    };
  }, []);

  // Auto-scroll
  useEffect(() => {
    if (autoScroll) {
      terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const toggleListener = async () => {
    sound.playTick();
    try {
      if (isListening) {
        await fetch('/api/syslog/stop', { method: 'POST' });
        setIsListening(false);
      } else {
        await fetch('/api/syslog/start', { method: 'POST' });
        setIsListening(true);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleSimulateBurst = async () => {
    sound.playAlertPulse();
    try {
      await fetch('/api/syslog/simulate', { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
  };

  const formatLogLine = (line: string) => {
    if (crtMode) {
      return <span className="crt-phosphor font-mono">{line}</span>;
    }

    let colorClass = 'text-zinc-300';
    if (line.includes('[ALERT]')) {
      colorClass = 'text-rose-400 font-semibold';
    } else if (line.includes('[WARN]')) {
      colorClass = 'text-amber-300';
    } else if (line.includes('[INFO]')) {
      colorClass = 'text-violet-300';
    } else if (line.includes('[ERROR]')) {
      colorClass = 'text-rose-500 font-bold';
    }

    return <span className={colorClass}>{line}</span>;
  };

  const filteredLogs = logs.filter(l => l.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="space-y-6">
      {/* Control Bar */}
      <div className="bonanza-card p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/10 text-violet-400 border border-indigo-500/20">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-white font-bold flex items-center space-x-2 font-grotesk">
              <span>Port 5140 Real-Time Syslog Stream</span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono flex items-center space-x-1 ${
                wsConnected ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
              }`}>
                {wsConnected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                <span>{wsConnected ? 'WS LIVE' : 'WS OFFLINE'}</span>
              </span>
            </h3>
            <p className="text-xs text-zinc-400 font-mono">Multi-threaded UDP / TCP RFC 5424 socket listener</p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* CRT Scanline Toggle */}
          <button
            onClick={() => {
              setCrtMode(!crtMode);
              sound.playTick();
            }}
            className={`px-3 py-2 rounded-xl text-xs font-mono flex items-center space-x-1.5 transition-all border ${
              crtMode
                ? 'bg-indigo-600/25 text-violet-300 border-indigo-400/50 shadow-[0_0_15px_rgba(99,102,241,0.25)]'
                : 'bg-white/5 border-white/10 text-zinc-400 hover:text-white'
            }`}
            title="Toggle Retro CRT Phosphor Scanlines"
          >
            <Tv className="w-3.5 h-3.5" />
            <span>{crtMode ? 'CRT ON' : 'CRT SCANLINES'}</span>
          </button>

          <button
            onClick={toggleListener}
            className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center space-x-1.5 transition-all ${
              isListening
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 hover:bg-rose-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
            }`}
          >
            {isListening ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop Port 5140</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Port 5140</span>
              </>
            )}
          </button>

          <button
            onClick={handleSimulateBurst}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-indigo-600 via-violet-600 to-purple-600 text-white shadow-glow-indigo hover:opacity-90 transition-all flex items-center space-x-1.5 font-grotesk"
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Simulate Attack Burst</span>
          </button>

          <button
            onClick={() => {
              setLogs([]);
              sound.playTick();
            }}
            className="p-2 rounded-xl bg-zinc-900 text-zinc-400 hover:text-white border border-white/10 transition-all"
            title="Clear Console"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal Console (with CRT scanlines if enabled) */}
      <div className={`bonanza-card overflow-hidden border border-white/10 flex flex-col h-[580px] ${crtMode ? 'crt-screen' : ''}`}>
        {/* Terminal Header */}
        <div className="bg-[#0E0D18] px-4 py-2.5 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
            <span className="text-xs font-mono text-zinc-400 ml-2">syslog@netrashield-node-01: /var/log/syslog (port 5140)</span>
          </div>

          <div className="flex items-center space-x-3 text-xs">
            <input
              type="text"
              placeholder="Filter syslog terminal..."
              value={filter}
              onChange={e => setFilter(e.target.value)}
              className="bg-[#141221] border border-white/10 rounded-lg px-2.5 py-1 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-indigo-400 font-mono w-48"
            />
            <label className="flex items-center space-x-1.5 text-zinc-400 cursor-pointer font-mono">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={e => setAutoScroll(e.target.checked)}
                className="rounded accent-indigo-400"
              />
              <span>Auto-scroll</span>
            </label>
          </div>
        </div>

        {/* Terminal Body */}
        <div className="flex-1 p-4 bg-[#08070F] font-mono text-xs overflow-y-auto space-y-1 select-text">
          {filteredLogs.length === 0 ? (
            <div className="text-zinc-500 text-center py-20 font-sans">
              Syslog console listening for UDP packets on 127.0.0.1:5140. Trigger "Simulate Attack Burst" above to view live stream.
            </div>
          ) : (
            filteredLogs.map((log, idx) => (
              <div key={idx} className="leading-relaxed hover:bg-white/[0.04] px-1 rounded transition-colors">
                {formatLogLine(log)}
              </div>
            ))
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
};
