import React, { useState } from 'react';
import {
  ShieldAlert,
  Terminal,
  Database,
  Grid,
  Settings,
  Play,
  Download,
  Search,
  Sliders,
  Maximize2,
  Minimize2,
  Activity,
  Zap,
  Cpu,
  ShieldCheck,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import { ThreatTriageView } from './ThreatTriageView';
import { LiveSyslogView } from './LiveSyslogView';
import { IocManagerView } from './IocManagerView';
import { MitreMatrixView } from './MitreMatrixView';
import { SettingsView } from './SettingsView';
import type { TriageResult, IncidentStatus } from '../types/soc';

interface EmbeddedSocWorkbenchProps {
  triageData: TriageResult | null;
  loading: boolean;
  onRunTriage: (fd: FormData) => void;
  onUpdateStatus: (alertId: string, newStatus: IncidentStatus) => void;
  isFullScreen?: boolean;
  onToggleFullScreen?: () => void;
}

export const EmbeddedSocWorkbench: React.FC<EmbeddedSocWorkbenchProps> = ({
  triageData,
  loading,
  onRunTriage,
  onUpdateStatus,
  isFullScreen = false,
  onToggleFullScreen
}) => {
  const [activeTab, setActiveTab] = useState<'triage' | 'syslog' | 'ioc' | 'mitre' | 'settings'>('triage');

  const tabs = [
    { id: 'triage' as const, label: 'Threat Triage', icon: ShieldAlert },
    { id: 'syslog' as const, label: 'Live Syslog (Port 5140)', icon: Terminal },
    { id: 'ioc' as const, label: 'IOC Watchlist', icon: Database },
    { id: 'mitre' as const, label: 'MITRE Matrix', icon: Grid },
    { id: 'settings' as const, label: 'Settings', icon: Settings },
  ];

  return (
    <div className="w-full bg-[#0A0D14] rounded-2xl border border-white/10 overflow-hidden flex flex-col shadow-2xl">
      {/* Top Application Header Bar */}
      <div className="bg-[#07090E] px-4 py-3 border-b border-white/10 flex flex-wrap items-center justify-between gap-3">
        {/* Navigation Tabs */}
        <div className="flex items-center space-x-1 overflow-x-auto scrollbar-none py-0.5">
          {tabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3.5 py-1.5 rounded-xl text-xs font-medium flex items-center space-x-2 transition-all ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-400/30 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                    : 'text-slate-400 hover:text-white hover:bg-white/5 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Right Status Indicator & Expand Control */}
        <div className="flex items-center space-x-3 text-xs">
          <div className="flex items-center space-x-2 font-mono text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="hidden sm:inline">Engine Online</span>
          </div>
          {onToggleFullScreen && (
            <button
              onClick={onToggleFullScreen}
              className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-slate-300 hover:text-white transition-colors"
              title={isFullScreen ? 'Exit Full Screen' : 'Full Screen'}
            >
              {isFullScreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>

      {/* Main Viewport */}
      <div className="p-4 sm:p-6 overflow-y-auto max-h-[750px]">
        {activeTab === 'triage' && (
          <ThreatTriageView
            triageData={triageData}
            loading={loading}
            onRunTriage={onRunTriage}
            onUpdateStatus={onUpdateStatus}
          />
        )}
        {activeTab === 'syslog' && <LiveSyslogView />}
        {activeTab === 'ioc' && <IocManagerView />}
        {activeTab === 'mitre' && <MitreMatrixView />}
        {activeTab === 'settings' && <SettingsView />}
      </div>
    </div>
  );
};
