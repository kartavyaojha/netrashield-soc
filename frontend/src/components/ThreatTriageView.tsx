import React, { useState, useEffect } from 'react';
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
  Server,
  FileText,
  UserX,
  History,
  CheckSquare,
  Square,
  ShieldCheck,
  CornerDownRight
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
import { ProcessTreeGraph } from './ProcessTreeGraph';
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

  // Investigation Verdict & Playbook State
  const [verdictLoading, setVerdictLoading] = useState(false);
  const [verdictData, setVerdictData] = useState<any | null>(null);
  const [remediationChecklist, setRemediationChecklist] = useState<{ id: number; text: string; done: boolean }[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);

  // Containment Confirmation Modal State
  const [containModalOpen, setContainModalOpen] = useState(false);
  const [containActionType, setContainActionType] = useState<'ISOLATE_HOST' | 'BLOCK_DEST_IP' | 'DISABLE_USER_ACCOUNT' | null>(null);
  const [containTargetEntity, setContainTargetEntity] = useState('');
  const [containAnalystNote, setContainAnalystNote] = useState('');
  const [containConfirmed, setContainConfirmed] = useState(false);
  const [containLoading, setContainLoading] = useState(false);
  const [containError, setContainError] = useState<string | null>(null);
  const [containSuccessMsg, setContainSuccessMsg] = useState<string | null>(null);

  // Fetch incident verdict & audit logs when drawer opens
  useEffect(() => {
    if (!activeIncident) {
      setVerdictData(null);
      setAuditLogs([]);
      setRemediationChecklist([]);
      return;
    }
    const fetchVerdictAndAudit = async () => {
      setVerdictLoading(true);
      try {
        const [vRes, aRes] = await Promise.all([
          fetch(`/api/incidents/${encodeURIComponent(activeIncident.alert_id)}/verdict`),
          fetch(`/api/incidents/${encodeURIComponent(activeIncident.alert_id)}/audit`)
        ]);
        if (vRes.ok) {
          const vData = await vRes.json();
          setVerdictData(vData);
          if (vData.remediation_checklist && Array.isArray(vData.remediation_checklist)) {
            setRemediationChecklist(
              vData.remediation_checklist.map((step: string, idx: number) => ({
                id: idx,
                text: step,
                done: false
              }))
            );
          }
        }
        if (aRes.ok) {
          const aData = await aRes.json();
          setAuditLogs(aData.audit_logs || []);
        }
      } catch (e) {
        console.error('Failed fetching incident verdict & audit trail:', e);
      } finally {
        setVerdictLoading(false);
      }
    };
    fetchVerdictAndAudit();
  }, [activeIncident?.alert_id]);

  const openContainmentModal = (action: 'ISOLATE_HOST' | 'BLOCK_DEST_IP' | 'DISABLE_USER_ACCOUNT') => {
    sound.playTick();
    setContainActionType(action);
    setContainError(null);
    setContainConfirmed(false);
    setContainAnalystNote('');
    if (action === 'ISOLATE_HOST') {
      setContainTargetEntity(activeIncident?.host || 'WIN-DC-01');
    } else if (action === 'BLOCK_DEST_IP') {
      setContainTargetEntity(activeIncident?.dest_ip || '185.220.101.5');
    } else {
      setContainTargetEntity('SYSTEM_SERVICE_ACCOUNT');
    }
    setContainModalOpen(true);
  };

  const handleExecuteContainment = async () => {
    if (!activeIncident || !containActionType || !containConfirmed) return;
    setContainLoading(true);
    setContainError(null);
    try {
      const res = await fetch(`/api/incidents/${encodeURIComponent(activeIncident.alert_id)}/contain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action_type: containActionType,
          target_entity: containTargetEntity,
          analyst_note: containAnalystNote,
          confirmed: true
        })
      });
      if (res.ok) {
        sound.playAlertPulse();
        const data = await res.json();
        onUpdateStatus(activeIncident.alert_id, 'Contained');
        setActiveIncident(prev => prev ? { ...prev, status: 'Contained' } : null);
        setContainSuccessMsg(`Containment action executed: ${containTargetEntity} is contained.`);
        setContainModalOpen(false);
        setTimeout(() => setContainSuccessMsg(null), 5000);
        // Refresh audit logs
        const aRes = await fetch(`/api/incidents/${encodeURIComponent(activeIncident.alert_id)}/audit`);
        if (aRes.ok) {
          const aData = await aRes.json();
          setAuditLogs(aData.audit_logs || []);
        }
      } else {
        const err = await res.json();
        setContainError(err.detail || 'Containment action failed');
      }
    } catch (e: any) {
      setContainError(e.message || 'Connection error');
    } finally {
      setContainLoading(false);
    }
  };

  const toggleChecklistStep = (id: number) => {
    sound.playTick();
    setRemediationChecklist(prev =>
      prev.map(step => (step.id === id ? { ...step, done: !step.done } : step))
    );
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

  // Structured KQL-Style Search Token Parser
  const parseKqlQuery = (query: string) => {
    const tokens: {
      severity?: string;
      host?: string;
      mitre?: string;
      riskOp?: '>' | '<' | '>=' | '<=' | '=';
      riskVal?: number;
      status?: string;
      freeText: string[];
    } = { freeText: [] };

    const parts = query.trim().split(/\s+/);
    for (const part of parts) {
      if (!part) continue;
      const lower = part.toLowerCase();
      if (lower.startsWith('severity:')) {
        tokens.severity = part.substring(9).toUpperCase();
      } else if (lower.startsWith('host:')) {
        tokens.host = part.substring(5).toLowerCase();
      } else if (lower.startsWith('mitre:')) {
        tokens.mitre = part.substring(6).toLowerCase();
      } else if (lower.startsWith('status:')) {
        tokens.status = part.substring(7).toLowerCase();
      } else if (lower.startsWith('risk:')) {
        const match = part.substring(5).match(/^([><]=?|=)?(\d+(\.\d+)?)$/);
        if (match) {
          tokens.riskOp = (match[1] as any) || '>=';
          tokens.riskVal = parseFloat(match[2]);
        }
      } else {
        tokens.freeText.push(lower);
      }
    }
    return tokens;
  };

  const alerts = triageData?.alerts || [];
  const kql = parseKqlQuery(searchQuery);

  const filteredAlerts = alerts.filter(a => {
    // 1. Severity filter dropdown & KQL token
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    if (kql.severity && a.severity.toUpperCase() !== kql.severity) return false;
    // 2. Host filter token
    if (kql.host && !a.host.toLowerCase().includes(kql.host)) return false;
    // 3. Mitre technique token
    if (kql.mitre && !a.mitre_id.toLowerCase().includes(kql.mitre) && !a.mitre_name.toLowerCase().includes(kql.mitre)) return false;
    // 4. Status token
    if (kql.status && !a.status.toLowerCase().includes(kql.status)) return false;
    // 5. Risk score inequality token
    if (kql.riskVal !== undefined) {
      const op = kql.riskOp || '>=';
      if (op === '>' && !(a.risk_score > kql.riskVal)) return false;
      if (op === '>=' && !(a.risk_score >= kql.riskVal)) return false;
      if (op === '<' && !(a.risk_score < kql.riskVal)) return false;
      if (op === '<=' && !(a.risk_score <= kql.riskVal)) return false;
      if (op === '=' && Math.abs(a.risk_score - kql.riskVal) > 0.01) return false;
    }
    // 6. Free text keywords match
    if (kql.freeText.length > 0) {
      const combined = `${a.alert_id} ${a.host} ${a.detection_title} ${a.process_command} ${a.mitre_id} ${a.dest_ip}`.toLowerCase();
      for (const word of kql.freeText) {
        if (!combined.includes(word)) return false;
      }
    }
    return true;
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
                      { name: 'CRITICAL', count: 1, color: '#f43f5e' },
                      { name: 'HIGH', count: 2, color: '#f59e0b' },
                      { name: 'MEDIUM', count: 1, color: '#6366f1' },
                      { name: 'LOW', count: 1, color: '#10b981' }
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={4}
                    dataKey="count"
                  >
                    {(triageData?.distributions?.severity || [
                      { name: 'CRITICAL', count: 1, color: '#f43f5e' },
                      { name: 'HIGH', count: 2, color: '#f59e0b' },
                      { name: 'MEDIUM', count: 1, color: '#6366f1' },
                      { name: 'LOW', count: 1, color: '#10b981' }
                    ]).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '0.75rem', fontSize: '11px' }}
                    itemStyle={{ color: '#ffffff' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* MITRE ATT&CK Top Techniques Bar */}
            <div className="flex flex-col items-center justify-center bg-[#13121E]/80 rounded-xl p-3 border border-white/5">
              <p className="text-xs font-medium text-zinc-400 mb-2 font-mono">Top MITRE Techniques</p>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart
                  data={triageData?.distributions?.mitre || [
                    { technique: 'T1059.001', count: 3 },
                    { technique: 'T1003.001', count: 2 },
                    { technique: 'T1053.005', count: 1 },
                    { technique: 'T1110', count: 1 }
                  ]}
                  layout="vertical"
                  margin={{ top: 5, right: 10, left: 20, bottom: 5 }}
                >
                  <XAxis type="number" stroke="#71717a" fontSize={10} tickLine={false} />
                  <YAxis dataKey="technique" type="category" stroke="#a1a1aa" fontSize={10} tickLine={false} width={75} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', borderRadius: '0.75rem', fontSize: '11px' }}
                    itemStyle={{ color: '#ffffff' }}
                  />
                  <Bar dataKey="count" fill="#818cf8" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* BOTTOM PANEL: Correlated Incident Queue with VIEW TOGGLE (Table vs Graph) */}
      <div className="bonanza-card p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-3">
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
                  placeholder="KQL: severity:CRITICAL risk:>80 host:WIN..."
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
                href="/api/triage/export/pdf"
                download="netrashield_executive_report.pdf"
                className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-[#FF4D2D]/15 hover:bg-[#FF4D2D]/25 text-[#FF4D2D] border border-[#FF4D2D]/40 flex items-center space-x-1 transition-all shadow-sm"
                title="Download Executive Incident PDF Report"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export PDF</span>
              </a>

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

        {/* KQL Quick Filter Suggestion Chips */}
        {viewMode === 'table' && (
          <div className="flex flex-wrap items-center gap-1.5 mb-4 text-[11px] font-mono text-zinc-400">
            <span className="text-zinc-500 font-medium">KQL Quick Filters:</span>
            {[
              { label: 'severity:CRITICAL', query: 'severity:CRITICAL' },
              { label: 'risk:>75', query: 'risk:>75' },
              { label: 'mitre:T1059.001', query: 'mitre:T1059.001' },
              { label: 'host:WIN-DC-01', query: 'host:WIN-DC-01' },
              { label: 'status:Open', query: 'status:Open' },
            ].map(hint => (
              <button
                key={hint.label}
                onClick={() => {
                  sound.playTick();
                  setSearchQuery(prev => (prev ? `${prev} ${hint.query}` : hint.query));
                }}
                className="px-2 py-0.5 rounded-md bg-white/5 hover:bg-white/10 text-zinc-300 border border-white/5 hover:border-white/20 transition-colors"
              >
                {hint.label}
              </button>
            ))}
            {searchQuery && (
              <button
                onClick={() => {
                  sound.playTick();
                  setSearchQuery('');
                }}
                className="px-2 py-0.5 rounded-md text-zinc-400 hover:text-white bg-zinc-800/80 border border-white/5"
              >
                Clear
              </button>
            )}
          </div>
        )}

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
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-sans font-semibold ${getSeverityBadge(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-zinc-200 font-bold">{alert.risk_score}</td>
                      <td className="py-3 px-3 text-zinc-400">{alert.mitre_id || '-'}</td>
                      <td className="py-3 px-3 text-zinc-200 font-sans max-w-[200px] truncate">{alert.detection_title}</td>
                      <td className="py-3 px-3 text-zinc-400 max-w-[220px] truncate">
                        {alert.process_command || alert.process_image || '-'}
                      </td>
                      <td className="py-3 px-3 text-zinc-300 text-[11px]">{alert.dest_ip || '-'}</td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-sans border ${
                          alert.status === 'Contained'
                            ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                            : alert.status === 'Escalated'
                            ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                            : alert.status === 'Resolved'
                            ? 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                            : 'bg-zinc-900 text-zinc-400 border-white/10'
                        }`}>
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

      {/* SLIDE-OVER INCIDENT CASE DOSSIER */}
      {activeIncident && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm transition-opacity">
          <div className="w-full max-w-2xl h-full bg-[#12111E]/98 border-l border-white/15 p-6 flex flex-col justify-between overflow-y-auto animate-in slide-in-from-right shadow-2xl">
            <div className="space-y-5">
              {/* Drawer Top Header */}
              <div className="flex items-center justify-between pb-4 border-b border-white/10">
                <div className="flex items-center space-x-3">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${getSeverityBadge(activeIncident.severity)}`}>
                    {activeIncident.severity}
                  </span>
                  <h3 className="text-lg font-bold text-white font-mono">{activeIncident.alert_id}</h3>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-white/5 text-zinc-300 font-mono border border-white/10">
                    Status: {activeIncident.status}
                  </span>
                </div>
                <button
                  onClick={() => setActiveIncident(null)}
                  className="p-1 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {containSuccessMsg && (
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center space-x-2">
                  <Check className="w-4 h-4 text-emerald-400" />
                  <span>{containSuccessMsg}</span>
                </div>
              )}

              {/* Title & Host info */}
              <div>
                <h4 className="text-base font-semibold text-white">{activeIncident.detection_title}</h4>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Observed on host: <span className="text-violet-400 font-mono font-medium">{activeIncident.host}</span>
                </p>
              </div>

              {/* Visual Attack Storyline (ProcessTreeGraph) */}
              <ProcessTreeGraph incident={activeIncident} />

              {/* Investigation Verdict & Plain-English Explanation */}
              <div className="p-4 rounded-xl bg-[#161524] border border-white/10 space-y-3 font-sans">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-[#FF4D2D]" />
                    <span>Investigation Verdict & Attack Narrative</span>
                  </span>
                  {verdictLoading && (
                    <span className="text-[10px] font-mono text-zinc-400 animate-pulse">Evaluating...</span>
                  )}
                </div>

                {verdictData ? (
                  <div className="space-y-3">
                    <div className="p-3 rounded-lg bg-black/40 border border-white/5 text-xs text-zinc-200 leading-relaxed font-sans">
                      {verdictData.verdict}
                    </div>

                    <div className="text-xs text-zinc-300">
                      <span className="text-zinc-500 font-mono uppercase text-[10px] block mb-1">Primary Recommendation:</span>
                      <p className="font-medium text-emerald-300 font-sans">{verdictData.recommendation}</p>
                    </div>

                    {/* Checkable Remediation Checklist */}
                    {remediationChecklist.length > 0 && (
                      <div className="space-y-1.5 pt-2 border-t border-white/5">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 block mb-1">
                          MITRE-Tailored Remediation Checklist:
                        </span>
                        {remediationChecklist.map(step => (
                          <div
                            key={step.id}
                            onClick={() => toggleChecklistStep(step.id)}
                            className={`flex items-start space-x-2.5 p-2 rounded-lg cursor-pointer transition-colors ${
                              step.done ? 'bg-emerald-500/10 text-emerald-300' : 'bg-black/30 text-zinc-300 hover:bg-black/50'
                            }`}
                          >
                            <button type="button" className="mt-0.5 text-zinc-400">
                              {step.done ? (
                                <CheckSquare className="w-4 h-4 text-emerald-400" />
                              ) : (
                                <Square className="w-4 h-4 text-zinc-500" />
                              )}
                            </button>
                            <span className={`text-xs select-none ${step.done ? 'line-through opacity-70' : ''}`}>
                              {step.text}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-xs text-zinc-500 py-2 font-mono">
                    Loading automated playbook analysis...
                  </div>
                )}
              </div>

              {/* Governed Containment Response Buttons */}
              <div className="p-4 rounded-xl bg-[#18131E] border border-rose-500/20 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-white font-mono uppercase">
                    <Lock className="w-3.5 h-3.5 text-[#FF4D2D]" />
                    <span>Governed Containment Actions (HITL Protected)</span>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-400">Requires Confirmation</span>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => openContainmentModal('ISOLATE_HOST')}
                    className="px-3 py-2 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-500/40 text-indigo-200 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
                  >
                    <Server className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Isolate Host ({activeIncident.host})</span>
                  </button>

                  <button
                    onClick={() => openContainmentModal('BLOCK_DEST_IP')}
                    className="px-3 py-2 rounded-lg bg-rose-950/80 hover:bg-rose-900 border border-rose-500/40 text-rose-200 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
                  >
                    <Lock className="w-3.5 h-3.5 text-[#FF4D2D]" />
                    <span>Block Dest IP ({activeIncident.dest_ip || 'Adversary'})</span>
                  </button>

                  <button
                    onClick={() => openContainmentModal('DISABLE_USER_ACCOUNT')}
                    className="px-3 py-2 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-500/40 text-amber-200 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
                  >
                    <UserX className="w-3.5 h-3.5 text-amber-400" />
                    <span>Disable Account</span>
                  </button>
                </div>
              </div>

              {/* Status Changer */}
              <div className="p-3.5 rounded-xl bg-[#161524] border border-white/5">
                <p className="text-xs font-medium text-zinc-400 mb-2 font-mono">Triage Investigation State:</p>
                <div className="flex flex-wrap gap-2">
                  {(['Open', 'Investigating', 'Escalated', 'Contained', 'Resolved', 'Closed'] as IncidentStatus[]).map(st => (
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

              {/* Shannon Entropy & Risk Metrics */}
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

              {/* Normalized ECS Telemetry */}
              <div>
                <p className="text-xs font-medium text-zinc-400 mb-1 font-mono">Normalized ECS Telemetry:</p>
                <pre className="p-3 rounded-xl bg-black border border-white/10 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-40">
                  {JSON.stringify(activeIncident.raw_ecs || activeIncident, null, 2)}
                </pre>
              </div>

              {/* Chronological Incident Audit Trail */}
              <div className="p-4 rounded-xl bg-[#0E0D17] border border-white/10 space-y-3 font-mono">
                <div className="flex items-center space-x-2 text-xs font-bold text-white uppercase tracking-wider">
                  <History className="w-3.5 h-3.5 text-violet-400" />
                  <span>Incident Audit Ledger & Governance Log</span>
                </div>

                {auditLogs.length === 0 ? (
                  <p className="text-xs text-zinc-500 py-1 font-sans">
                    No containment or status audit records logged for this incident yet.
                  </p>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {auditLogs.map((log: any) => (
                      <div
                        key={log.audit_id || log.id}
                        className="p-2.5 rounded-lg bg-[#151424] border border-white/5 text-[11px] space-y-1"
                      >
                        <div className="flex items-center justify-between text-zinc-400">
                          <span className="px-1.5 py-0.2 rounded bg-indigo-500/20 text-violet-300 font-semibold">
                            {log.action_type}
                          </span>
                          <span className="text-zinc-500 text-[10px]">{log.executed_at?.slice(0, 19)}</span>
                        </div>
                        <div className="text-zinc-200">
                          <span className="text-zinc-500">Target:</span> {log.target_entity}
                        </div>
                        {log.analyst_note && (
                          <div className="text-zinc-400 italic font-sans text-xs">
                            "{log.analyst_note}"
                          </div>
                        )}
                        <div className="text-[10px] text-zinc-500 flex items-center space-x-1">
                          <span>Status transition:</span>
                          <span className="text-zinc-400">{log.previous_status || 'Open'}</span>
                          <span>→</span>
                          <span className="text-emerald-400 font-semibold">{log.new_status}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
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

      {/* Governed Containment Confirmation Modal */}
      {containModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-[#141221] border border-rose-500/40 rounded-2xl p-6 max-w-lg w-full space-y-4 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-white/10">
              <div className="flex items-center space-x-2 text-rose-400 font-grotesk font-bold">
                <AlertTriangle className="w-5 h-5 text-[#FF4D2D]" />
                <span>Confirm Active Threat Containment</span>
              </div>
              <button
                onClick={() => setContainModalOpen(false)}
                className="p-1 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {containError && (
              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
                {containError}
              </div>
            )}

            <div className="space-y-3 font-sans text-xs text-zinc-300">
              <p>
                You are about to execute action <strong className="text-white font-mono">{containActionType}</strong> against target:
              </p>

              <div>
                <label className="text-[10px] font-mono uppercase text-zinc-400 block mb-1">Target Entity / Host / IP</label>
                <input
                  type="text"
                  value={containTargetEntity}
                  onChange={e => setContainTargetEntity(e.target.value)}
                  className="w-full bg-[#0D0B18] border border-white/15 rounded-xl px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-indigo-400"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono uppercase text-zinc-400 block mb-1">Analyst Rationale / Incident Note</label>
                <textarea
                  rows={3}
                  value={containAnalystNote}
                  onChange={e => setContainAnalystNote(e.target.value)}
                  placeholder="State the observed indicators, ticket ID, or justification for isolation..."
                  className="w-full bg-[#0D0B18] border border-white/15 rounded-xl px-3 py-2 text-white text-xs focus:outline-none focus:border-indigo-400 resize-none font-sans"
                />
              </div>

              <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/20 flex items-start space-x-2.5">
                <input
                  type="checkbox"
                  id="containConfirmCheckbox"
                  checked={containConfirmed}
                  onChange={e => setContainConfirmed(e.target.checked)}
                  className="mt-0.5 rounded accent-[#FF4D2D] cursor-pointer"
                />
                <label htmlFor="containConfirmCheckbox" className="text-zinc-200 select-none cursor-pointer leading-tight">
                  I confirm this containment action under SOP-BLUE-4. The action will immediately isolate the entity, append any IP to the local IOC store, and log to the tamper-evident audit ledger.
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-white/10">
              <button
                onClick={() => setContainModalOpen(false)}
                className="px-4 py-2 rounded-xl text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-white/10"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteContainment}
                disabled={!containConfirmed || containLoading}
                className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#FF4D2D] hover:bg-[#ff3b18] shadow-sm disabled:opacity-40 transition-all flex items-center space-x-1.5"
              >
                {containLoading ? (
                  <span className="inline-block animate-spin rounded-full h-3.5 w-3.5 border-2 border-white border-t-transparent" />
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5" />
                    <span>Execute Containment</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
