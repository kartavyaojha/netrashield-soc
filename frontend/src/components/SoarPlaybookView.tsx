import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Play,
  CheckCircle2,
  RotateCcw,
  Terminal,
  Lock,
  Server,
  UserX,
  Zap,
  AlertTriangle,
  Clock,
  ArrowRight,
  Search,
  Activity,
  Layers,
  Check
} from 'lucide-react';
import { sound } from '../utils/audio';

interface Playbook {
  id: string;
  name: string;
  category: string;
  description: string;
  target_type: string;
  risk_level: string;
  estimated_duration_ms: number;
  steps: string[];
}

interface SoarAction {
  action_id: string;
  timestamp: string;
  playbook_id: string;
  playbook_name: string;
  target: string;
  alert_id: string;
  status: string;
  logs: string[];
  can_rollback: boolean;
}

export const SoarPlaybookView: React.FC = () => {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [history, setHistory] = useState<SoarAction[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'playbooks' | 'history'>('playbooks');
  const [executingId, setExecutingId] = useState<string | null>(null);
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [targetInput, setTargetInput] = useState('');
  const [alertIdInput, setAlertIdInput] = useState('');
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[INIT] NetraShield Autonomous SOAR Subsystem v2.4 initialized',
    '[READY] 5 Zero-Trust containment playbooks loaded into memory',
    '[STATUS] BGP edge blackholing & eBPF host isolation daemon active'
  ]);

  useEffect(() => {
    fetchPlaybooks();
    fetchHistory();
  }, []);

  const fetchPlaybooks = async () => {
    try {
      const res = await fetch('/api/soar/playbooks');
      if (res.ok) {
        const data = await res.json();
        setPlaybooks(data.playbooks || []);
        if (data.playbooks && data.playbooks.length > 0) {
          setSelectedPlaybook(data.playbooks[0]);
          setDefaultTarget(data.playbooks[0]);
        }
      }
    } catch (e) {
      console.error('Failed to load playbooks', e);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/soar/history');
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      }
    } catch (e) {
      console.error('Failed to load SOAR history', e);
    }
  };

  const setDefaultTarget = (pb: Playbook) => {
    if (pb.target_type === 'IP_ADDRESS') {
      setTargetInput('185.220.101.5');
    } else if (pb.target_type === 'HOSTNAME') {
      setTargetInput('srv-prod-api-01');
    } else if (pb.target_type === 'PROCESS_PID') {
      setTargetInput('4912 (powershell.exe)');
    } else if (pb.target_type === 'USERNAME') {
      setTargetInput('admin.svc_backup');
    } else if (pb.target_type === 'DOMAIN') {
      setTargetInput('c2-beacon.dark-telemetry.io');
    }
    setAlertIdInput(`ALT-${Math.floor(1000 + Math.random() * 9000)}`);
  };

  const handleSelectPlaybook = (pb: Playbook) => {
    sound.playTick();
    setSelectedPlaybook(pb);
    setDefaultTarget(pb);
  };

  const handleExecute = async () => {
    if (!selectedPlaybook || !targetInput.trim()) return;

    sound.playChirp();
    setExecutingId(selectedPlaybook.id);
    setLoading(true);

    // Initial terminal logs
    setTerminalLogs(prev => [
      ...prev,
      `[EXEC_START] Triggering ${selectedPlaybook.name}...`,
      `[TARGET] Enforcing containment against ${targetInput}...`
    ]);

    try {
      const res = await fetch('/api/soar/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          playbook_id: selectedPlaybook.id,
          target: targetInput.trim(),
          alert_id: alertIdInput.trim() || undefined
        })
      });

      if (res.ok) {
        const data = await res.json();
        sound.playAlertPulse();
        setTerminalLogs(prev => [
          ...prev,
          ...(data.action.logs || []),
          `[VERIFIED] Action ${data.action.action_id} committed to ledger.`
        ]);
        await fetchHistory();
      }
    } catch (e) {
      console.error('Execution failed', e);
      setTerminalLogs(prev => [...prev, `[ERROR] Execution failed: ${String(e)}`]);
    } finally {
      setExecutingId(null);
      setLoading(false);
    }
  };

  const handleRollback = async (actionId: string) => {
    sound.playTick();
    try {
      const res = await fetch('/api/soar/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_id: actionId })
      });
      if (res.ok) {
        sound.playChirp();
        setTerminalLogs(prev => [
          ...prev,
          `[ROLLBACK] Reverted action ${actionId} successfully.`
        ]);
        await fetchHistory();
      }
    } catch (e) {
      console.error('Rollback failed', e);
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'FIREWALL':
        return <Lock className="w-4 h-4 text-rose-400" />;
      case 'ENDPOINT':
        return <Server className="w-4 h-4 text-indigo-400" />;
      case 'PROCESS':
        return <Zap className="w-4 h-4 text-amber-400" />;
      case 'IDENTITY':
        return <UserX className="w-4 h-4 text-purple-400" />;
      case 'NETWORK':
        return <Activity className="w-4 h-4 text-cyan-400" />;
      default:
        return <ShieldAlert className="w-4 h-4 text-indigo-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner KPI Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bonanza-card p-4 rounded-xl border border-indigo-500/20 bg-[#12111B]">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Active Quarantines</span>
            <Lock className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-grotesk text-white">
            {history.filter(h => h.status === 'SUCCESS').length} Rules
          </div>
          <div className="text-[11px] text-emerald-400 mt-1 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            Enforcing at Edge
          </div>
        </div>

        <div className="bonanza-card p-4 rounded-xl border border-indigo-500/20 bg-[#12111B]">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Mean Time To Contain (MTTC)</span>
            <Clock className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-grotesk text-indigo-300">
            118 ms
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Autonomous Sub-Second Speed</div>
        </div>

        <div className="bonanza-card p-4 rounded-xl border border-indigo-500/20 bg-[#12111B]">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Playbook Engine Status</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-grotesk text-white">ACTIVE</div>
          <div className="text-[11px] text-indigo-400 mt-1">5 Playbooks Armed</div>
        </div>

        <div className="bonanza-card p-4 rounded-xl border border-indigo-500/20 bg-[#12111B]">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Audit Ledger Integrity</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-grotesk text-emerald-400">100%</div>
          <div className="text-[11px] text-slate-400 mt-1">Cryptographically Signed</div>
        </div>
      </div>

      {/* Main Two-Column Workflow */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Playbook Catalog (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
              <h3 className="text-base font-bold text-white font-grotesk">
                Autonomous Blue-Team Playbook Catalog
              </h3>
            </div>
            <div className="flex items-center gap-1 bg-[#161522] p-1 rounded-lg border border-white/5 text-xs">
              <button
                onClick={() => {
                  sound.playTick();
                  setActiveTab('playbooks');
                }}
                className={`px-3 py-1 rounded-md font-medium transition-all ${
                  activeTab === 'playbooks'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Playbooks ({playbooks.length})
              </button>
              <button
                onClick={() => {
                  sound.playTick();
                  setActiveTab('history');
                }}
                className={`px-3 py-1 rounded-md font-medium transition-all ${
                  activeTab === 'history'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Audit Ledger ({history.length})
              </button>
            </div>
          </div>

          {activeTab === 'playbooks' ? (
            <div className="space-y-3">
              {playbooks.map(pb => {
                const isSelected = selectedPlaybook?.id === pb.id;
                return (
                  <div
                    key={pb.id}
                    onClick={() => handleSelectPlaybook(pb)}
                    className={`cursor-pointer p-4 rounded-xl transition-all border ${
                      isSelected
                        ? 'bg-[#181628] border-indigo-500/50 shadow-lg shadow-indigo-500/10'
                        : 'bg-[#12111B] border-white/5 hover:border-indigo-500/30'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-[#1D1B2D] border border-white/5">
                          {getCategoryIcon(pb.category)}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-semibold text-white">{pb.name}</h4>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-700/40">
                              {pb.id}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 mt-1 line-clamp-1">
                            {pb.description}
                          </p>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-2 py-0.5 rounded">
                          ~{pb.estimated_duration_ms}ms
                        </span>
                      </div>
                    </div>

                    {isSelected && (
                      <div className="mt-4 pt-3 border-t border-white/5 text-xs">
                        <div className="text-slate-400 font-semibold mb-2 flex items-center gap-1.5">
                          <Layers className="w-3.5 h-3.5 text-indigo-400" />
                          <span>Execution Kill-Chain Steps:</span>
                        </div>
                        <div className="space-y-1.5 pl-2 border-l-2 border-indigo-500/40">
                          {pb.steps.map((st, idx) => (
                            <div key={idx} className="flex items-center gap-2 text-slate-300 text-[11px]">
                              <span className="w-4 h-4 rounded-full bg-indigo-900/60 text-indigo-300 text-[9px] flex items-center justify-center font-mono">
                                {idx + 1}
                              </span>
                              <span>{st}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            /* Audit Ledger History Table */
            <div className="overflow-x-auto rounded-xl border border-white/10 bg-[#12111B]">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-[#181628] text-slate-400 uppercase font-mono text-[10px] border-b border-white/5">
                  <tr>
                    <th className="py-2.5 px-3">Action ID</th>
                    <th className="py-2.5 px-3">Playbook</th>
                    <th className="py-2.5 px-3">Target</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 font-mono">
                  {history.map(item => (
                    <tr key={item.action_id} className="hover:bg-white/[0.02]">
                      <td className="py-2.5 px-3 text-indigo-300">{item.action_id}</td>
                      <td className="py-2.5 px-3 text-white font-sans">{item.playbook_name}</td>
                      <td className="py-2.5 px-3 text-rose-300">{item.target}</td>
                      <td className="py-2.5 px-3 text-slate-400">{item.timestamp}</td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            item.status === 'SUCCESS'
                              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
                              : 'bg-slate-800 text-slate-400 border border-white/10'
                          }`}
                        >
                          {item.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {item.can_rollback ? (
                          <button
                            onClick={() => handleRollback(item.action_id)}
                            className="inline-flex items-center gap-1 px-2 py-1 rounded bg-amber-950/60 hover:bg-amber-900/80 text-amber-300 border border-amber-500/30 text-[10px] transition-all"
                          >
                            <RotateCcw className="w-3 h-3" />
                            <span>Rollback</span>
                          </button>
                        ) : (
                          <span className="text-slate-500 text-[10px] italic">Reverted</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: Execution Form & Real-time Console (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Action Trigger Box */}
          <div className="bonanza-card p-5 rounded-xl border border-indigo-500/30 bg-[#12111B] space-y-4">
            <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <h3 className="text-sm font-bold text-white font-grotesk">
                  Containment Execution Console
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-900/50 text-indigo-300 border border-indigo-500/20">
                AUTH: LEVEL-4 Blue-Team
              </span>
            </div>

            {selectedPlaybook ? (
              <div className="space-y-3">
                <div>
                  <label className="text-xs text-slate-400 block mb-1">
                    Selected Playbook:
                  </label>
                  <div className="text-xs font-semibold text-white bg-[#181628] p-2.5 rounded-lg border border-white/10 flex items-center justify-between">
                    <span>{selectedPlaybook.name}</span>
                    <span className="text-[10px] font-mono text-indigo-400">{selectedPlaybook.category}</span>
                  </div>
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">
                    Target Indicator ({selectedPlaybook.target_type}):
                  </label>
                  <input
                    type="text"
                    value={targetInput}
                    onChange={e => setTargetInput(e.target.value)}
                    placeholder={`e.g. ${selectedPlaybook.target_type}`}
                    className="w-full bg-[#181628] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-indigo-500 transition-colors"
                  />
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">
                    Correlated Incident Alert ID (Optional):
                  </label>
                  <input
                    type="text"
                    value={alertIdInput}
                    onChange={e => setAlertIdInput(e.target.value)}
                    placeholder="e.g. ALT-1002"
                    className="w-full bg-[#181628] border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-indigo-500 transition-colors"
                  />
                </div>

                <button
                  onClick={handleExecute}
                  disabled={loading || !targetInput.trim()}
                  className="w-full py-2.5 px-4 rounded-xl font-bold text-xs uppercase tracking-wider text-white bg-gradient-to-r from-rose-600 via-indigo-600 to-violet-600 hover:from-rose-500 hover:to-violet-500 transition-all shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <>
                      <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                      <span>Dispatching Containment...</span>
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4 text-amber-300" />
                      <span>Execute Containment Playbook</span>
                    </>
                  )}
                </button>
              </div>
            ) : (
              <div className="text-xs text-slate-400 text-center py-6">
                Select a playbook from the catalog to prepare execution.
              </div>
            )}
          </div>

          {/* Real-time Terminal Execution Output */}
          <div className="rounded-xl border border-indigo-500/20 bg-[#0A0912] p-4 font-mono text-[11px] space-y-2 shadow-inner">
            <div className="flex items-center justify-between text-slate-500 text-[10px] border-b border-white/5 pb-2">
              <div className="flex items-center gap-1.5">
                <Terminal className="w-3 h-3 text-indigo-400" />
                <span>SOAR-DAEMON@NETRASHIELD:~$</span>
              </div>
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                STREAMING
              </span>
            </div>

            <div className="h-44 overflow-y-auto space-y-1 text-slate-300 scrollbar-thin scrollbar-thumb-indigo-900 pr-1">
              {terminalLogs.map((log, index) => {
                let colorClass = 'text-slate-300';
                if (log.startsWith('[OK]')) colorClass = 'text-emerald-400 font-semibold';
                if (log.startsWith('[EXEC') || log.startsWith('[TARGET]')) colorClass = 'text-cyan-300';
                if (log.startsWith('[VERIFIED]')) colorClass = 'text-violet-300 font-bold';
                if (log.startsWith('[ERROR]')) colorClass = 'text-rose-400 font-bold';
                if (log.startsWith('[ROLLBACK]')) colorClass = 'text-amber-400';

                return (
                  <div key={index} className={`leading-relaxed ${colorClass}`}>
                    {log}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
