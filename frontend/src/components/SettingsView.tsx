import React, { useState, useEffect } from 'react';
import { Settings, Save, CheckCircle2, ShieldCheck, HeartPulse, RefreshCw } from 'lucide-react';
import { SystemSettings, HealthStatus } from '../types/soc';

export const SettingsView: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings>({
    worker_threads: 4,
    max_memory_ceiling_mb: 2048,
    server_port: 8000,
    syslog_port: 5140,
    default_export_format: 'json',
    min_risk_threshold: 40.0,
    contamination: 0.05,
    n_estimators: 100
  });

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  const fetchSettingsAndHealth = async () => {
    try {
      setLoading(true);
      const [resSet, resHealth] = await Promise.all([
        fetch('/api/settings'),
        fetch('/api/health')
      ]);
      const dataSet = await resSet.json();
      const dataHealth = await resHealth.json();
      setSettings(dataSet);
      setHealth(dataHealth);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettingsAndHealth();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
      if (res.ok) {
        setSavedSuccess(true);
        setTimeout(() => setSavedSuccess(false), 3000);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const subsystems = health?.subsystems || {
    ecs_parser_engine: { name: 'ECS Parser Engine', status: 'ONLINE', healthy: true },
    sigma_compiler: { name: 'Sigma YAML Compiler', status: 'ONLINE', healthy: true },
    isolation_forest_model: { name: 'IsolationForest Model', status: 'ONLINE', healthy: true },
    sqlite_incident_store: { name: 'SQLite Incident Store', status: 'ONLINE', healthy: true },
    syslog_socket: { name: 'UDP/TCP Syslog Socket', status: 'LISTENING', healthy: true },
  };

  return (
    <div className="space-y-6">
      {/* 5-ITEM SYSTEM HEALTH MATRIX */}
      <div className="glass-panel p-6">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-white font-bold flex items-center space-x-2">
            <HeartPulse className="w-5 h-5 text-rose-400" />
            <span>NetraShield 5-Item Subsystem Health Matrix</span>
          </h4>
          <button
            onClick={fetchSettingsAndHealth}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
            title="Refresh Diagnostics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {Object.entries(subsystems).map(([key, sub]) => (
            <div key={key} className="p-3.5 rounded-xl bg-slate-900/50 border border-white/5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-slate-400 uppercase">Subsystem</span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                  sub.healthy
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                }`}>
                  {sub.status}
                </span>
              </div>
              <h5 className="text-xs font-semibold text-slate-200">{sub.name}</h5>
              <div className="flex items-center space-x-1.5 text-[11px] text-slate-400">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Operational</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CONFIGURATION FORM */}
      <div className="glass-panel p-6 max-w-2xl">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-white font-bold flex items-center space-x-2">
            <Settings className="w-5 h-5 text-cyan-400" />
            <span>Detection Policy & Server Configuration</span>
          </h4>
          <span className="text-xs font-mono text-slate-400">config.yaml sync</span>
        </div>

        {savedSuccess && (
          <div className="mb-4 p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>Configuration changes successfully committed to config.yaml</span>
          </div>
        )}

        <form onSubmit={handleSave} className="space-y-4 text-xs font-sans">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-slate-400 block mb-1">Worker Thread Pool (cores)</label>
              <input
                type="number"
                min="1"
                max="32"
                value={settings.worker_threads}
                onChange={e => setSettings({ ...settings, worker_threads: Number(e.target.value) })}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Max Memory Ceiling (MB)</label>
              <input
                type="number"
                step="128"
                value={settings.max_memory_ceiling_mb}
                onChange={e => setSettings({ ...settings, max_memory_ceiling_mb: Number(e.target.value) })}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-slate-400 block mb-1">FastAPI REST Server Port</label>
              <input
                type="number"
                value={settings.server_port}
                onChange={e => setSettings({ ...settings, server_port: Number(e.target.value) })}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Syslog UDP/TCP Port</label>
              <input
                type="number"
                value={settings.syslog_port}
                onChange={e => setSettings({ ...settings, syslog_port: Number(e.target.value) })}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-slate-400 block mb-1">Default Triage Export Format</label>
              <select
                value={settings.default_export_format}
                onChange={e => setSettings({ ...settings, default_export_format: e.target.value })}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
              >
                <option value="json">Structured JSON (.json)</option>
                <option value="csv">Flattened CSV (.csv)</option>
              </select>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Default Minimum Risk Threshold</label>
              <input
                type="number"
                min="10"
                max="90"
                value={settings.min_risk_threshold}
                onChange={e => setSettings({ ...settings, min_risk_threshold: Number(e.target.value) })}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-400"
              />
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              className="py-2.5 px-6 rounded-xl font-semibold text-slate-950 bg-cyan-500 hover:bg-cyan-400 transition-all shadow-cyan-glow flex items-center space-x-2"
            >
              <Save className="w-4 h-4" />
              <span>Save to config.yaml</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
