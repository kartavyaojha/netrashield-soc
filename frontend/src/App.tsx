import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Terminal,
  Database,
  Grid,
  Settings,
  Shield,
  Activity,
  Play,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { ThreatTriageView } from './components/ThreatTriageView';
import { LiveSyslogView } from './components/LiveSyslogView';
import { IocManagerView } from './components/IocManagerView';
import { MitreMatrixView } from './components/MitreMatrixView';
import { SettingsView } from './components/SettingsView';
import { TriageResult, IncidentStatus } from './types/soc';

type ActiveTab = 'triage' | 'syslog' | 'ioc' | 'mitre' | 'settings';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('triage');
  const [triageData, setTriageData] = useState<TriageResult | null>(null);
  const [loadingTriage, setLoadingTriage] = useState(false);
  const [engineStatus, setEngineStatus] = useState('ML Engine: Online • Port 5140: Ready');

  // Load initial demo triage run on mount
  useEffect(() => {
    runInitialTriage();
    checkHealth();
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        if (data.engine_status) {
          setEngineStatus(data.engine_status);
        }
      }
    } catch (e) {
      // Ignore network errors on startup
    }
  };

  const runInitialTriage = async () => {
    try {
      setLoadingTriage(true);
      const fd = new FormData();
      fd.append('use_demo', 'true');
      fd.append('min_risk_threshold', '40');
      fd.append('contamination', '0.05');
      fd.append('worker_threads', '4');

      const res = await fetch('/api/triage/run', {
        method: 'POST',
        body: fd
      });
      if (res.ok) {
        const data = await res.json();
        setTriageData(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingTriage(false);
    }
  };

  const handleRunTriage = async (formData: FormData) => {
    try {
      setLoadingTriage(true);
      const res = await fetch('/api/triage/run', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setTriageData(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingTriage(false);
    }
  };

  const handleUpdateStatus = async (alertId: string, newStatus: IncidentStatus) => {
    try {
      await fetch(`/api/incidents/${alertId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      // Update local state
      if (triageData) {
        const updatedAlerts = triageData.alerts.map(a =>
          a.alert_id === alertId ? { ...a, status: newStatus } : a
        );
        setTriageData({ ...triageData, alerts: updatedAlerts });
      }
    } catch (e) {
      console.error(e);
    }
  };

  const navItems = [
    { id: 'triage' as ActiveTab, label: 'Threat Triage', icon: ShieldAlert },
    { id: 'syslog' as ActiveTab, label: 'Live Syslog Stream', icon: Terminal },
    { id: 'ioc' as ActiveTab, label: 'IOC Watchlist', icon: Database },
    { id: 'mitre' as ActiveTab, label: 'MITRE ATT&CK Matrix', icon: Grid },
    { id: 'settings' as ActiveTab, label: 'System Settings', icon: Settings }
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden text-slate-100 font-sans">
      {/* LEFT FROSTED GLASS SIDEBAR */}
      <aside className="w-64 glass-panel m-3 mr-0 flex flex-col justify-between p-4 border border-white/10 shrink-0">
        <div>
          {/* Branded Header */}
          <div className="flex items-center space-x-3 px-2 py-3 border-b border-white/10">
            <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 text-white shadow-cyan-glow">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="font-bold text-sm tracking-wide text-white">NetraShield SOC</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/30">
                  v2.4.0
                </span>
              </div>
              <p className="text-[10px] text-slate-400 italic">Kartavya's Blue-Team Workbench</p>
            </div>
          </div>

          {/* Nav Items */}
          <nav className="mt-6 space-y-1.5">
            {navItems.map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-cyan-glow'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/40 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Engine Status Bottom Pill */}
        <div className="p-3 rounded-xl bg-slate-950/60 border border-white/5 text-[11px] font-mono">
          <div className="flex items-center space-x-2 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-semibold truncate">{engineStatus}</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Hybrid Risk Fusion: Sigma + ML + IOC</p>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col overflow-hidden m-3">
        {/* TOP GLASS HEADER BAR */}
        <header className="glass-panel px-6 py-3.5 mb-3 flex items-center justify-between border border-white/10 shrink-0">
          <div className="flex items-center space-x-3">
            <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Active Session:</span>
            <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900/60 border border-white/10 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span className="text-slate-300">Telemetry Stream Active</span>
              <span className="text-slate-500">•</span>
              <span className="text-cyan-400">{triageData?.total_events || 30} Events Parsed</span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => runInitialTriage()}
              className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-500/20 to-indigo-500/20 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/30 transition-all flex items-center space-x-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Load Synthetic Attack Demo</span>
            </button>
          </div>
        </header>

        {/* MAIN TAB VIEW VIEWPORT */}
        <main className="flex-1 overflow-y-auto pr-1">
          {activeTab === 'triage' && (
            <ThreatTriageView
              triageData={triageData}
              loading={loadingTriage}
              onRunTriage={handleRunTriage}
              onUpdateStatus={handleUpdateStatus}
            />
          )}

          {activeTab === 'syslog' && <LiveSyslogView />}

          {activeTab === 'ioc' && <IocManagerView />}

          {activeTab === 'mitre' && <MitreMatrixView />}

          {activeTab === 'settings' && <SettingsView />}
        </main>
      </div>
    </div>
  );
};

export default App;
