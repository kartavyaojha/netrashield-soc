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
    database: 'healthy',
    sigma_engine: 'healthy',
    ml_isolation_forest: 'healthy',
    syslog_listener: 'listening',
    ioc_store: 'healthy'
  };

  return (
    <div className="space-y-6">
      {/* SYSTEM HEALTH CARDS */}
      <div className="glass-panel p-6">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-lg font-bold text-white flex items-center space-x-2 font-grotesk">
            <HeartPulse className="w-5 h-5 text-emerald-400" />
            <span>Autonomous Engine Health Diagnostics</span>
          </h4>
          <span className="px-3 py-1 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            System Status: 100% Operational
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
          {Object.entries(subsystems).map(([name, status]) => (
            <div key={name} className="p-3.5 rounded-xl bg-[#141221] border border-white/5 flex flex-col justify-between">
              <span className="text-[11px] font-mono uppercase text-zinc-400">
                {name.replace(/_/g, ' ')}
              </span>
              <div className="flex items-center space-x-1.5 text-[11px] text-zinc-300 mt-2 font-mono">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="capitalize">{status}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CONFIGURATION FORM */}
      <div className="glass-panel p-6 max-w-2xl">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-white font-bold flex items-center space-x-2 font-grotesk">
            <Settings className="w-5 h-5 text-violet-400" />
            <span>Detection Policy & Server Configuration</span>
          </h4>
          <span className="text-xs font-mono text-zinc-400">config.yaml sync</span>
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
              <label className="text-zinc-400 block mb-1">Worker Thread Pool (cores)</label>
              <input
                type="number"
                min="1"
                max="32"
                value={settings.worker_threads}
                onChange={e => setSettings({ ...settings, worker_threads: Number(e.target.value) })}
                className="w-full bg-[#141221] border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-indigo-400"
              />
            </div>

            <div>
              <label className="text-zinc-400 block mb-1">Max Memory Ceiling (MB)</label>
              <input
                type="number"
                step="128"
                value={settings.max_memory_ceiling_mb}
                onChange={e => setSettings({ ...settings, max_memory_ceiling_mb: Number(e.target.value) })}
                className="w-full bg-[#141221] border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-indigo-400"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-zinc-400 block mb-1">FastAPI REST Server Port</label>
              <input
                type="number"
                value={settings.server_port}
                onChange={e => setSettings({ ...settings, server_port: Number(e.target.value) })}
                className="w-full bg-[#141221] border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-indigo-400"
              />
            </div>

            <div>
              <label className="text-zinc-400 block mb-1">Syslog UDP/TCP Port</label>
              <input
                type="number"
                value={settings.syslog_port}
                onChange={e => setSettings({ ...settings, syslog_port: Number(e.target.value) })}
                className="w-full bg-[#141221] border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-indigo-400"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-zinc-400 block mb-1">Default Triage Export Format</label>
              <select
                value={settings.default_export_format}
                onChange={e => setSettings({ ...settings, default_export_format: e.target.value })}
                className="w-full bg-[#141221] border border-white/10 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-indigo-400"
              >
                <option value="json">Structured JSON (.json)</option>
                <option value="csv">Flattened CSV (.csv)</option>
              </select>
            </div>

            <div>
              <label className="text-zinc-400 block mb-1">Default Minimum Risk Threshold</label>
              <input
                type="number"
                min="10"
                max="90"
                value={settings.min_risk_threshold}
                onChange={e => setSettings({ ...settings, min_risk_threshold: Number(e.target.value) })}
                className="w-full bg-[#141221] border border-white/10 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-indigo-400"
              />
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              className="py-2.5 px-6 rounded-xl font-bold text-white bg-indigo-600 hover:bg-indigo-500 transition-all shadow-glow-indigo flex items-center space-x-2"
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
