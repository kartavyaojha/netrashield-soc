import React, { useState, useEffect } from 'react';
import { ShieldCheck, Cpu, RefreshCw, CheckCircle, Sliders, Layers } from 'lucide-react';
import { MitreTacticGroup } from '../types/soc';

export const MitreMatrixView: React.FC = () => {
  const [matrixData, setMatrixData] = useState<MitreTacticGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [contamination, setContamination] = useState(0.05);
  const [estimators, setEstimators] = useState(100);
  const [retraining, setRetraining] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Sigma Module Toggles
  const [sigmaToggles, setSigmaToggles] = useState({
    process_creation: true,
    network_connection: true,
    registry_persistence: true,
    powershell_scriptblock: true,
  });

  const fetchMitre = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/mitre');
      const data = await res.json();
      setMatrixData(data.matrix || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMitre();
  }, []);

  const handleRetrain = async () => {
    try {
      setRetraining(true);
      const res = await fetch('/api/ml/retrain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contamination: contamination,
          n_estimators: estimators
        })
      });
      const data = await res.json();
      setToastMessage(data.message || 'IsolationForest model successfully retrained.');
      setTimeout(() => setToastMessage(null), 4000);
    } catch (e) {
      console.error(e);
    } finally {
      setRetraining(false);
    }
  };

  const toggleSigmaModule = (key: keyof typeof sigmaToggles) => {
    setSigmaToggles(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="space-y-6">
      {/* Toast Confirmation */}
      {toastMessage && (
        <div className="p-3.5 rounded-xl bg-indigo-600/20 border border-indigo-500/40 text-violet-300 text-xs flex items-center space-x-2 animate-in fade-in">
          <CheckCircle className="w-4 h-4 text-emerald-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* TOP ROW: ML TUNER & SIGMA MODULE TOGGLES */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ML Sensitivity Card */}
        <div className="lg:col-span-6 glass-panel p-5">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-white font-semibold flex items-center space-x-2 font-grotesk">
              <Cpu className="w-5 h-5 text-violet-400" />
              <span>Isolation Forest ML Sensitivity Tuner</span>
            </h4>
            <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/20 text-violet-300 font-mono">
              Unsupervised Outlier Engine
            </span>
          </div>

          <div className="space-y-4 text-xs">
            <div>
              <div className="flex justify-between text-zinc-300 mb-1">
                <span>Contamination Factor</span>
                <span className="font-mono text-violet-400 font-bold">{(contamination * 100).toFixed(1)}%</span>
              </div>
              <input
                type="range"
                min="0.01"
                max="0.20"
                step="0.005"
                value={contamination}
                onChange={e => setContamination(Number(e.target.value))}
                className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-indigo-400"
              />
              <p className="text-[10px] text-zinc-500 mt-0.5">Expected anomaly ratio in baseline normal training telemetry</p>
            </div>

            <div>
              <div className="flex justify-between text-zinc-300 mb-1">
                <span>Estimators (Tree Count)</span>
                <span className="font-mono text-purple-400 font-bold">{estimators} Trees</span>
              </div>
              <input
                type="range"
                min="50"
                max="500"
                step="25"
                value={estimators}
                onChange={e => setEstimators(Number(e.target.value))}
                className="w-full h-1.5 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-purple-400"
              />
              <p className="text-[10px] text-zinc-500 mt-0.5">Forest complexity; higher values improve stability across entropy vectors</p>
            </div>

            <button
              onClick={handleRetrain}
              disabled={retraining}
              className="w-full py-2.5 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-glow-indigo flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${retraining ? 'animate-spin' : ''}`} />
              <span>{retraining ? 'Retraining Baseline...' : 'Retrain IsolationForest'}</span>
            </button>
          </div>
        </div>

        {/* Sigma Modules Glass Card */}
        <div className="lg:col-span-6 glass-panel p-5">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-white font-semibold flex items-center space-x-2 font-grotesk">
              <Layers className="w-5 h-5 text-violet-400" />
              <span>Sigma Detection Modules (YAML)</span>
            </h4>
            <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/20 text-violet-300 font-mono">
              Auto-Seeded 1001..1004
            </span>
          </div>

          <div className="space-y-3 text-xs">
            {[
              { id: 'process_creation', label: 'Process Creation Rules (Sysmon EID 1)', rule: 'NS-SIG-1001 & 1002' },
              { id: 'network_connection', label: 'Network Connection & SSH Brute Force (EID 3 / Syslog)', rule: 'NS-SIG-1004' },
              { id: 'registry_persistence', label: 'Persistence & Scheduled Tasks (schtasks)', rule: 'NS-SIG-1003' },
              { id: 'powershell_scriptblock', label: 'PowerShell Encoded Command & Cradle Inspection', rule: 'NS-SIG-1001' }
            ].map(mod => {
              const active = (sigmaToggles as any)[mod.id];
              return (
                <div
                  key={mod.id}
                  onClick={() => toggleSigmaModule(mod.id as any)}
                  className="flex items-center justify-between p-2.5 rounded-xl bg-[#141221] border border-white/5 hover:border-indigo-500/30 cursor-pointer transition-all"
                >
                  <div>
                    <p className="font-medium text-zinc-200">{mod.label}</p>
                    <p className="text-[10px] text-violet-400 font-mono mt-0.5">{mod.rule}</p>
                  </div>
                  <div
                    className={`w-9 h-5 flex items-center rounded-full p-0.5 transition-colors ${
                      active ? 'bg-indigo-600' : 'bg-zinc-800'
                    }`}
                  >
                    <div
                      className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform ${
                        active ? 'translate-x-4' : 'translate-x-0'
                      }`}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* INTERACTIVE MITRE ATT&CK MATRIX GRID */}
      <div className="glass-panel p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h4 className="text-lg font-bold text-white flex items-center space-x-2 font-grotesk">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <span>Enterprise MITRE ATT&CK Matrix Grid</span>
            </h4>
            <p className="text-xs text-zinc-400">Live correlation hits across tactical defense columns</p>
          </div>
          <button
            onClick={fetchMitre}
            className="px-3 py-1.5 rounded-xl text-xs bg-zinc-900 text-zinc-300 hover:text-white border border-white/10 flex items-center space-x-1"
          >
            <RefreshCw className="w-3 h-3" />
            <span>Refresh Hits</span>
          </button>
        </div>

        {/* Matrix Columns */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {matrixData.map(tactic => (
            <div key={tactic.tactic_id} className="space-y-3">
              {/* Column Header */}
              <div className="p-3 rounded-xl bg-[#141221] border border-white/10 text-center">
                <span className="text-[10px] font-mono text-violet-400">{tactic.tactic_id}</span>
                <h5 className="text-xs font-bold text-white uppercase tracking-wider mt-0.5">
                  {tactic.tactic_name}
                </h5>
                <div className="mt-1">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                    tactic.total_hits > 0 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-zinc-900 text-zinc-500'
                  }`}>
                    {tactic.total_hits} Hits
                  </span>
                </div>
              </div>

              {/* Technique Cards */}
              <div className="space-y-2">
                {tactic.techniques.map(tech => {
                  const hasHits = tech.count > 0;
                  return (
                    <div
                      key={tech.id}
                      className={`p-3 rounded-xl border transition-all ${
                        hasHits
                          ? 'bg-rose-500/10 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.2)]'
                          : 'bg-[#141221]/60 border-white/5 hover:border-white/15'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] text-violet-300">{tech.id}</span>
                        {hasHits && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 bg-rose-500 text-white rounded font-bold">
                            {tech.count}
                          </span>
                        )}
                      </div>
                      <p className="text-xs font-semibold text-zinc-200 mt-1">{tech.name}</p>
                      <p className="text-[10px] text-zinc-500 mt-1 line-clamp-2">{tech.description}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
