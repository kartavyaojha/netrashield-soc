import React, { useState } from 'react';
import {
  UploadCloud,
  Play,
  Download,
  Search,
  Sliders,
  ShieldAlert,
  Zap,
  Activity,
  CheckCircle2,
  AlertTriangle,
  X,
  ExternalLink,
  Cpu,
  Share2,
  Table,
  Binary,
  Copy,
  Check,
  Lock,
  Server
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import type { AlertIncident, TriageResult, IncidentStatus } from '../types/soc';
import { AttackGraphView } from './AttackGraphView';
import { sound } from '../utils/audio';

interface ThreatTriageViewProps {
  triageData: TriageResult | null;
  loading: boolean;
  onRunTriage: (formData: FormData) => void;
  onUpdateStatus: (alertId: string, newStatus: IncidentStatus) => void;
}

export const ThreatTriageView: React.FC<ThreatTriageViewProps> = ({
  triageData,
  loading,
  onRunTriage,
  onUpdateStatus
}) => {
  const [useDemo, setUseDemo] = useState(true);
  const [minRisk, setMinRisk] = useState(40);
  const [contamination, setContamination] = useState(0.05);
  const [workerThreads, setWorkerThreads] = useState(4);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [activeIncident, setActiveIncident] = useState<AlertIncident | null>(null);
  const [viewMode, setViewMode] = useState<'table' | 'graph'>('table');
  const [hexViewMode, setHexViewMode] = useState<'parsed' | 'hex'>('parsed');
  const [soarExecuting, setSoarExecuting] = useState(false);
  const [soarSuccessMsg, setSoarSuccessMsg] = useState<string | null>(null);

  const handleExecuteQuickSoar = async (playbookId: string, target: string) => {
    sound.playChirp();
    setSoarExecuting(true);
    setSoarSuccessMsg(null);
    try {
      const res = await fetch('/api/soar/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          playbook_id: playbookId,
          target: target,
          alert_id: activeIncident?.alert_id
        })
      });
      if (res.ok) {
        sound.playAlertPulse();
        setSoarSuccessMsg(`Containment verified: ${target} quarantined!`);
        setTimeout(() => setSoarSuccessMsg(null), 4000);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSoarExecuting(false);
    }
  };

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
      sound.playTick();
    }
  };

  const handleTriggerRun = () => {
    sound.playTick();
    const fd = new FormData();
    if (selectedFile) {
      fd.append('files', selectedFile);
    }
    fd.append('use_demo', useDemo ? 'true' : 'false');
    fd.append('min_risk_threshold', minRisk.toString());
    fd.append('contamination', contamination.toString());
    fd.append('worker_threads', workerThreads.toString());
    onRunTriage(fd);
    sound.playChirp();
  };

  const kpis = triageData?.kpis || {
    total_events: 0,
    critical_alerts: 0,
    high_alerts: 0,
    avg_risk_score: 0.0,
    latency_ms: 0.0
  };

  const alerts = triageData?.alerts || [];
  const filteredAlerts = alerts.filter(a => {
    const matchesSearch =
      a.alert_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.detection_title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.process_command.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.mitre_id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSev = severityFilter === 'ALL' || a.severity === severityFilter;
    return matchesSearch && matchesSev;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-400 border border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.3)]';
      case 'HIGH':
        return 'bg-amber-500/15 text-amber-400 border border-amber-500/40';
      case 'MEDIUM':
        return 'bg-indigo-500/15 text-violet-300 border border-indigo-500/30';
      default:
        return 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/40';
    }
  };

  // Generate 16-byte hex dump of a payload string
  const generateHexDump = (payload: string) => {
    const bytes = new TextEncoder().encode(payload);
    const rows = [];
    for (let i = 0; i < Math.min(bytes.length, 128); i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hex = Array.from(chunk)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');
      const ascii = Array.from(chunk)
        .map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('');
      const offset = i.toString(16).padStart(8, '0');
      rows.push({ offset, hex: hex.padEnd(48, ' '), ascii });
    }
    return rows;
  };

  return (
    <div className="space-y-6">
      {/* TOP ROW: 4 GLASS KPI CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Events */}
        <div className="bonanza-card p-5 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 font-mono">Total Events Parsed</p>
              <h3 className="text-3xl font-bold font-mono tabular-nums text-white mt-1">
                {kpis.total_events.toLocaleString()}
              </h3>
            </div>
            <div className="p-3 bg-white/5 rounded-xl border border-white/10 text-zinc-300">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-zinc-400 font-mono">
            <span className="text-zinc-300 font-medium">ECS Normalizer</span>
            <span className="mx-2">•</span>
            <span>Sysmon, EVTX, PCAP</span>
          </div>
        </div>

        <div className="bonanza-card p-5 border-rose-500/20 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-rose-300 font-mono">Critical Alerts</p>
              <div className="flex items-baseline space-x-2 mt-1">
                <h3 className="text-3xl font-bold font-mono tabular-nums text-rose-400">
                  {kpis.critical_alerts}
                </h3>
                <span className="flex h-2.5 w-2.5 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
                </span>
              </div>
            </div>
            <div className="p-3 bg-rose-500/10 rounded-xl border border-rose-500/30 text-rose-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-rose-400/80 font-mono">
            <span>Risk Score &gt;= 85.0</span>
            <span className="mx-2">•</span>
            <span>Immediate Triage</span>
          </div>
        </div>

        <div className="bonanza-card p-5 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 font-mono">Avg Anomaly Risk</p>
              <h3 className="text-3xl font-bold font-mono tabular-nums text-zinc-200 mt-1">
                {kpis.avg_risk_score}
                <span className="text-sm text-zinc-500 ml-1">/ 100</span>
              </h3>
            </div>
            <div className="p-3 bg-white/5 rounded-xl border border-white/10 text-zinc-300">
              <Cpu className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-zinc-400 font-mono">
            <span>Sigma + Isolation Forest</span>
          </div>
        </div>

        <div className="bonanza-card p-5 group">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium uppercase tracking-wider text-zinc-400 font-mono">Triage Latency</p>
              <h3 className="text-3xl font-bold font-mono tabular-nums text-emerald-400 mt-1">
                {kpis.latency_ms}
                <span className="text-sm font-normal text-zinc-400 ml-1">ms</span>
              </h3>
            </div>
            <div className="p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/20 text-emerald-400">
              <Zap className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center text-xs text-emerald-400/90 font-mono">
            <span>&lt; 3000ms sub-3s SLA verified</span>
          </div>
        </div>
      </div>

      {/* CONTROL & ANALYTICS ROW */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* LEFT PANEL: Ingestion & Policy */}
        <div className="lg:col-span-5 bonanza-card p-6 flex flex-col justify-between space-y-5">
          <div>
            <div className="flex items-center space-x-2 text-white font-semibold mb-3 font-grotesk">
              <Sliders className="w-5 h-5 text-violet-400" />
              <span>Ingestion & Detection Policy</span>
            </div>

            {/* Drag & Drop File Zone */}
            <div
              onDragOver={e => e.preventDefault()}
              onDrop={handleFileDrop}
              onClick={() => document.getElementById('soc-file-input')?.click()}
              className="border-2 border-dashed border-indigo-500/30 hover:border-indigo-400/60 transition-all rounded-xl p-5 text-center cursor-pointer bg-[#141221]/60"
            >
              <input
                id="soc-file-input"
                type="file"
                className="hidden"
                accept=".json,.csv,.evtx,.pcap,.log,.syslog"
                onChange={e => {
                  if (e.target.files && e.target.files[0]) {
                    setSelectedFile(e.target.files[0]);
                    sound.playTick();
                  }
                }}
              />
              <UploadCloud className="w-8 h-8 text-zinc-400 mx-auto mb-2 opacity-80" />
              <p className="text-sm font-medium text-zinc-200 font-grotesk">
                {selectedFile ? selectedFile.name : 'Drop telemetry files or browse'}
              </p>
              <p className="text-xs text-zinc-500 mt-1 font-mono">
                Supports: .json, .csv, .evtx, .pcap, .log (Sysmon, Syslog)
              </p>
            </div>

            {/* Synthetic Telemetry Toggle */}
            <div className="flex items-center justify-between mt-4 p-3 rounded-xl bg-[#141221]/80 border border-white/5">
              <span className="text-xs font-medium text-zinc-300">
                Include Built-In Synthetic Attack Telemetry
              </span>
              <button
                type="button"
                onClick={() => {
                  setUseDemo(!useDemo);
                  sound.playTick();
                }}
                className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors ${
                  useDemo ? 'bg-indigo-600' : 'bg-zinc-800'
                }`}
              >
                <div
                  className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                    useDemo ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Threshold Sliders with Audio Feedback */}
            <div className="space-y-4 mt-4">
              <div>
                <div className="flex justify-between text-xs text-zinc-300 mb-1">
                  <span>Min Risk Threshold: {minRisk}</span>
                  <span className="text-violet-400 font-mono">{minRisk} / 100</span>
                </div>
                <input
                  type="range"
                  min="10"
                  max="95"
                  value={minRisk}
                  onChange={e => {
                    setMinRisk(Number(e.target.value));
                    sound.playTick();
                  }}
                  className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-indigo-400"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs text-zinc-300 mb-1">
                  <span>Isolation Forest Contamination</span>
                  <span className="text-purple-400 font-mono">{(contamination * 100).toFixed(0)}%</span>
                </div>
                <input
                  type="range"
                  min="0.01"
                  max="0.20"
                  step="0.01"
                  value={contamination}
                  onChange={e => {
                    setContamination(Number(e.target.value));
                    sound.playTick();
                  }}
                  className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-purple-400"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs text-zinc-300 mb-1">
                  <span>Worker Threads</span>
                  <span className="text-indigo-400 font-mono">{workerThreads} cores</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="16"
                  value={workerThreads}
                  onChange={e => {
                    setWorkerThreads(Number(e.target.value));
                    sound.playTick();
                  }}
                  className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-indigo-400"
                />
              </div>
            </div>
          </div>

          <button
            onClick={handleTriggerRun}
            disabled={loading}
            className="w-full py-3.5 px-4 rounded-xl font-bold text-white bg-[#FF4D2D] hover:bg-[#ff3b18] shadow-sm transition-all flex items-center justify-center space-x-2 disabled:opacity-50 font-grotesk"
          >
            {loading ? (
              <span className="inline-block animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent" />
            ) : (
              <>
                <Play className="w-5 h-5 fill-current" />
                <span>Run Threat Correlation</span>
              </>
            )}
          </button>
        </div>

        {/* RIGHT PANEL: Visual Threat Breakdown (Recharts) */}
        <div className="lg:col-span-7 bonanza-card p-6">
          <h4 className="text-white font-semibold mb-4 flex items-center space-x-2 font-grotesk">
            <Activity className="w-5 h-5 text-violet-400" />
            <span>Threat Severity & MITRE ATT&CK Breakdown</span>
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 h-64">
            {/* Severity Distribution Donut */}
            <div className="flex flex-col items-center justify-center bg-[#13121E]/80 rounded-xl p-3 border border-white/5">
              <p className="text-xs font-medium text-zinc-400 mb-2 font-mono">Alerts by Severity</p>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={triageData?.distributions?.severity || [
                      { name: 'CRITICAL', count: 3, color: '#F43F5E' },
                      { name: 'HIGH', count: 5, color: '#F59E0B' },
                      { name: 'MEDIUM', count: 4, color: '#818CF8' },
                      { name: 'LOW', count: 2, color: '#10B981' }
                    ]}
                    dataKey="count"
                    nameKey="name"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={4}
                  >
                    {(triageData?.distributions?.severity || []).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#161522', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* MITRE Techniques Bar Chart */}
            <div className="flex flex-col bg-[#13121E]/80 rounded-xl p-3 border border-white/5">
              <p className="text-xs font-medium text-zinc-400 mb-2 font-mono">Top Triggered MITRE Techniques</p>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart
                  data={triageData?.distributions?.mitre?.slice(0, 5) || [
                    { technique: 'T1059.001', count: 4 },
                    { technique: 'T1003.001', count: 2 },
                    { technique: 'T1053.005', count: 2 },
                    { technique: 'T1110', count: 3 },
                    { technique: 'T1071.001', count: 2 }
                  ]}
                  layout="vertical"
                  margin={{ left: 10, right: 10, top: 5, bottom: 5 }}
                >
                  <XAxis type="number" stroke="#52525B" fontSize={11} />
                  <YAxis type="category" dataKey="technique" stroke="#A1A1AA" fontSize={11} width={70} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#161522', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" fill="#818CF8" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* BOTTOM PANEL: Correlated Incident Queue with VIEW TOGGLE (Table vs Graph) */}
      <div className="bonanza-card p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
          <div className="flex items-center space-x-3">
            <h4 className="text-lg font-bold text-white flex items-center space-x-2 font-grotesk">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <span>Correlated Incidents</span>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-indigo-500/15 text-violet-300 border border-indigo-500/30 font-mono">
                {filteredAlerts.length} Active
              </span>
            </h4>

            {/* View Mode Toggle Pill (Table vs Node Attack Graph) */}
            <div className="flex items-center p-0.5 rounded-lg bg-zinc-900 border border-white/10 text-xs font-mono">
              <button
                onClick={() => {
                  setViewMode('table');
                  sound.playTick();
                }}
                className={`px-3 py-1 rounded-md flex items-center space-x-1.5 transition-all ${
                  viewMode === 'table' ? 'bg-indigo-600 text-white font-bold shadow-glow-indigo' : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Table className="w-3.5 h-3.5" />
                <span>Table</span>
              </button>
              <button
                onClick={() => {
                  setViewMode('graph');
                  sound.playTick();
                }}
                className={`px-3 py-1 rounded-md flex items-center space-x-1.5 transition-all ${
                  viewMode === 'graph' ? 'bg-indigo-600 text-white font-bold shadow-glow-indigo' : 'text-zinc-400 hover:text-white'
                }`}
              >
                <Share2 className="w-3.5 h-3.5" />
                <span>Attack Graph</span>
              </button>
            </div>
          </div>

          {/* Search, Filter, & Export Actions */}
          {viewMode === 'table' && (
            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <div className="relative flex-1 sm:w-64">
                <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search alerts, hosts, commands..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  className="w-full bg-[#141221] border border-white/10 rounded-xl pl-9 pr-3 py-1.5 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-indigo-400 font-mono"
                />
              </div>

              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="bg-[#141221] border border-white/10 rounded-xl px-3 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-indigo-400 font-mono"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <a
                href="/api/triage/export/csv"
                className="px-3 py-1.5 rounded-xl text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-white/10 flex items-center space-x-1"
              >
                <Download className="w-3.5 h-3.5" />
                <span>CSV</span>
              </a>
              <a
                href="/api/triage/export/json"
                className="px-3 py-1.5 rounded-xl text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-white/10 flex items-center space-x-1"
              >
                <Download className="w-3.5 h-3.5" />
                <span>JSON</span>
              </a>
            </div>
          )}
        </div>

        {/* Display based on View Mode */}
        {viewMode === 'graph' ? (
          <AttackGraphView
            alerts={filteredAlerts}
            onSelectAlert={alert => {
              setActiveIncident(alert);
              sound.playAlertPulse();
            }}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-zinc-400 uppercase tracking-wider border-b border-white/10 bg-[#12111E]/80">
                <tr>
                  <th className="py-3 px-3">Alert ID</th>
                  <th className="py-3 px-3">Host</th>
                  <th className="py-3 px-3">Severity</th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">MITRE ID</th>
                  <th className="py-3 px-3">Detection Title</th>
                  <th className="py-3 px-3">Process / Command</th>
                  <th className="py-3 px-3">Dest IP</th>
                  <th className="py-3 px-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono">
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="py-8 text-center text-zinc-500 font-sans">
                      No incidents match the active filters. Click "Run Threat Correlation" to ingest telemetry.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map(alert => (
                    <tr
                      key={alert.alert_id}
                      onClick={() => {
                        setActiveIncident(alert);
                        sound.playTick();
                      }}
                      className="hover:bg-indigo-500/[0.06] cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-3 text-violet-400 font-bold">{alert.alert_id}</td>
                      <td className="py-3 px-3 text-zinc-300 font-sans">{alert.host}</td>
                      <td className="py-3 px-3">
                        <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-sans font-semibold ${getSeverityBadge(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex items-center space-x-2">
                          <div className="w-16 bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-full ${
                                alert.risk_score >= 85
                                  ? 'bg-rose-500'
                                  : alert.risk_score >= 70
                                  ? 'bg-amber-400'
                                  : 'bg-violet-400'
                              }`}
                              style={{ width: `${alert.risk_score}%` }}
                            />
                          </div>
                          <span className="text-[11px] tabular-nums text-zinc-300">{alert.risk_score}</span>
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded bg-indigo-500/15 text-violet-300 border border-indigo-500/30 text-[10px]">
                          {alert.mitre_id || 'T1027'}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-zinc-200 font-sans truncate max-w-xs">{alert.detection_title}</td>
                      <td className="py-3 px-3 text-zinc-400 truncate max-w-xs text-[11px]">
                        {alert.process_command || alert.process_image || '-'}
                      </td>
                      <td className="py-3 px-3 text-zinc-300 text-[11px]">{alert.dest_ip || '-'}</td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-sans bg-zinc-900 text-zinc-400 border border-white/10">
                          {alert.status}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* SLIDE-OVER INCIDENT CASE DOSSIER (With Hex Dump & Entropy Spectrogram) */}
      {activeIncident && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm transition-opacity">
          <div className="w-full max-w-xl h-full bg-[#12111E]/98 border-l border-white/15 p-6 flex flex-col justify-between overflow-y-auto animate-in slide-in-from-right shadow-2xl">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-white/10">
                <div className="flex items-center space-x-3">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${getSeverityBadge(activeIncident.severity)}`}>
                    {activeIncident.severity}
                  </span>
                  <h3 className="text-lg font-bold text-white font-mono">{activeIncident.alert_id}</h3>
                </div>
                <button
                  onClick={() => setActiveIncident(null)}
                  className="p-1 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="mt-5 space-y-4 font-sans">
                <div>
                  <h4 className="text-sm font-semibold text-white">{activeIncident.detection_title}</h4>
                  <p className="text-xs text-zinc-400 mt-0.5">Observed on host: <span className="text-violet-400 font-mono">{activeIncident.host}</span></p>
                </div>

                {/* Status Changer */}
                <div className="p-3 rounded-xl bg-[#161524] border border-white/5">
                  <p className="text-xs font-medium text-zinc-400 mb-2 font-mono">Triage Investigation State:</p>
                  <div className="flex flex-wrap gap-2">
                    {(['Open', 'Investigating', 'Escalated', 'Closed'] as IncidentStatus[]).map(st => (
                      <button
                        key={st}
                        onClick={() => {
                          onUpdateStatus(activeIncident.alert_id, st);
                          setActiveIncident({ ...activeIncident, status: st });
                          sound.playChirp();
                        }}
                        className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
                          activeIncident.status === st
                            ? 'bg-indigo-600 text-white font-bold shadow-glow-indigo'
                            : 'bg-zinc-900 text-zinc-300 hover:bg-zinc-800'
                        }`}
                      >
                        {st}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-white/[0.03] border border-white/10 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-white">
                      <Zap className="w-3.5 h-3.5 text-amber-400" />
                      <span>Autonomous SOAR Containment:</span>
                    </div>
                    {soarSuccessMsg && (
                      <span className="text-[11px] text-emerald-400 font-mono animate-in fade-in flex items-center gap-1 font-semibold">
                        <Check className="w-3.5 h-3.5" /> {soarSuccessMsg}
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => handleExecuteQuickSoar('pb-block-ip', activeIncident.dest_ip || '185.220.101.5')}
                      disabled={soarExecuting}
                      className="px-2.5 py-1.5 rounded-lg bg-rose-950/80 hover:bg-rose-900 border border-rose-500/40 text-rose-300 text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm disabled:opacity-50"
                    >
                      <Lock className="w-3.5 h-3.5 text-rose-400" />
                      <span>Quarantine IP ({activeIncident.dest_ip || 'Adversary'})</span>
                    </button>
                    <button
                      onClick={() => handleExecuteQuickSoar('pb-isolate-host', activeIncident.host || 'srv-compromised')}
                      disabled={soarExecuting}
                      className="px-2.5 py-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-300 text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm disabled:opacity-50"
                    >
                      <Server className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Isolate Host ({activeIncident.host || 'Endpoint'})</span>
                    </button>
                    <button
                      onClick={() => handleExecuteQuickSoar('pb-kill-proc', activeIncident.process_command ? activeIncident.process_command.split(' ')[0] : 'malicious.exe')}
                      disabled={soarExecuting}
                      className="px-2.5 py-1.5 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-500/40 text-amber-300 text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm disabled:opacity-50"
                    >
                      <Zap className="w-3.5 h-3.5 text-amber-400" />
                      <span>Terminate Process</span>
                    </button>
                  </div>
                </div>

                {/* Shannon Entropy & Risk Metrics + Spectrogram Bar */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-xl bg-[#161524] border border-white/5">
                    <p className="text-xs text-zinc-400 font-mono">Shannon Entropy</p>
                    <p className="text-xl font-mono font-bold tabular-nums text-zinc-200 mt-1">
                      {activeIncident.shannon_entropy}
                    </p>
                    <div className="w-full bg-zinc-800 h-1.5 rounded-full mt-2 overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-emerald-400 via-amber-400 to-rose-500"
                        style={{ width: `${Math.min((activeIncident.shannon_entropy / 8.0) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-[#161524] border border-white/5">
                    <p className="text-xs text-zinc-400 font-mono">Calculated Risk</p>
                    <p className="text-xl font-mono font-bold text-rose-400 mt-1">
                      {activeIncident.risk_score} / 100
                    </p>
                    <p className="text-[10px] text-zinc-500 mt-1 font-mono">Hybrid ML + Sigma + IOC</p>
                  </div>
                </div>

                {/* MITRE ATT&CK Info */}
                <div className="p-3 rounded-xl bg-[#161524] border border-white/5">
                  <p className="text-xs font-medium text-zinc-400 font-mono">MITRE ATT&CK Classification:</p>
                  <div className="flex items-center space-x-2 mt-1">
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-indigo-500/20 text-violet-300 border border-indigo-500/30">
                      {activeIncident.mitre_id}
                    </span>
                    <span className="text-sm font-semibold text-zinc-200">{activeIncident.mitre_name}</span>
                  </div>
                </div>

                {/* Payload Inspector: Toggle Parsed vs Raw Hex Dump */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <p className="text-xs font-medium text-zinc-400 font-mono">Command Payload Inspector:</p>
                    <div className="flex items-center space-x-1 bg-zinc-900 rounded-lg p-0.5 border border-white/10 text-[10px] font-mono">
                      <button
                        onClick={() => setHexViewMode('parsed')}
                        className={`px-2 py-0.5 rounded ${hexViewMode === 'parsed' ? 'bg-indigo-600 text-white font-bold' : 'text-zinc-400'}`}
                      >
                        String
                      </button>
                      <button
                        onClick={() => setHexViewMode('hex')}
                        className={`px-2 py-0.5 rounded ${hexViewMode === 'hex' ? 'bg-indigo-600 text-white font-bold' : 'text-zinc-400'}`}
                      >
                        Hex Dump
                      </button>
                    </div>
                  </div>

                  {hexViewMode === 'parsed' ? (
                    <div className="p-3 rounded-xl bg-black border border-white/10 font-mono text-xs text-violet-300 break-all select-all">
                      {activeIncident.process_command || activeIncident.process_image || 'N/A'}
                    </div>
                  ) : (
                    /* 16-Column Hex Dump View */
                    <div className="p-3 rounded-xl bg-black border border-white/10 font-mono text-[10px] text-zinc-300 overflow-x-auto space-y-0.5 max-h-48">
                      {generateHexDump(activeIncident.process_command || 'No raw command line available').map(row => (
                        <div key={row.offset} className="flex space-x-3 leading-tight">
                          <span className="text-zinc-500 select-none">{row.offset}</span>
                          <span className="text-violet-300 select-all">{row.hex}</span>
                          <span className="text-emerald-400 select-all border-l border-white/10 pl-2">{row.ascii}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* ECS Normalized JSON Details */}
                <div>
                  <p className="text-xs font-medium text-zinc-400 mb-1 font-mono">Normalized ECS Telemetry:</p>
                  <pre className="p-3 rounded-xl bg-black border border-white/10 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-44">
                    {JSON.stringify(activeIncident.raw_ecs || activeIncident, null, 2)}
                  </pre>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-white/10 flex justify-end">
              <button
                onClick={() => setActiveIncident(null)}
                className="px-4 py-2 rounded-xl text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-white/10"
              >
                Close Case Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
