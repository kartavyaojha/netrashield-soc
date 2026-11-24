import React, { useState, useEffect } from 'react';
import { Database, Plus, Trash2, Search, CheckCircle2, AlertOctagon, Hash, Globe, Shield } from 'lucide-react';
import { IOCStore, IOCEntry } from '../types/soc';

export const IocManagerView: React.FC = () => {
  const [iocData, setIocData] = useState<IOCStore | null>(null);
  const [loading, setLoading] = useState(false);
  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupResult, setLookupResult] = useState<{ found: boolean; item?: IOCEntry; type?: string } | null>(null);

  // New IOC Form state
  const [newValue, setNewValue] = useState('');
  const [newType, setNewType] = useState<'sha256' | 'ips' | 'domains'>('sha256');
  const [newThreat, setNewThreat] = useState('');
  const [newSeverity, setNewSeverity] = useState('HIGH');
  const [newTags, setNewTags] = useState('');

  const fetchIocs = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/iocs');
      const data = await res.json();
      setIocData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIocs();
  }, []);

  const handleLookup = () => {
    if (!lookupQuery.trim() || !iocData) {
      setLookupResult(null);
      return;
    }
    const q = lookupQuery.toLowerCase().trim();
    // Check sha256
    const sha = iocData.iocs.sha256.find(i => i.value.toLowerCase() === q);
    if (sha) {
      setLookupResult({ found: true, item: sha, type: 'SHA256 File Signature' });
      return;
    }
    // Check ips
    const ip = iocData.iocs.ips.find(i => i.value === q);
    if (ip) {
      setLookupResult({ found: true, item: ip, type: 'Malicious IPv4 Endpoint' });
      return;
    }
    // Check domains
    const dom = iocData.iocs.domains.find(i => i.value.toLowerCase() === q);
    if (dom) {
      setLookupResult({ found: true, item: dom, type: 'C2 Domain Infrastructure' });
      return;
    }
    setLookupResult({ found: false });
  };

  const handleAddIoc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim() || !newThreat.trim()) return;

    try {
      const payload = {
        value: newValue.trim(),
        type: newType,
        threat: newThreat.trim(),
        severity: newSeverity,
        tags: newTags.split(',').map(t => t.trim()).filter(Boolean)
      };

      const res = await fetch('/api/iocs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setNewValue('');
        setNewThreat('');
        setNewTags('');
        fetchIocs();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleDeleteIoc = async (val: string, type: string) => {
    try {
      const res = await fetch(`/api/iocs?value=${encodeURIComponent(val)}&type=${type}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        fetchIocs();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const stats = iocData?.stats || { sha256_count: 0, domains_count: 0, ips_count: 0 };

  return (
    <div className="space-y-6">
      {/* 3 GLASS STAT CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-card p-5 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-400">SHA256 Signatures</p>
            <h3 className="text-3xl font-bold font-mono text-cyan-400 mt-1">{stats.sha256_count}</h3>
            <p className="text-xs text-slate-500 mt-1">Mimikatz, CobaltStrike, Loaders</p>
          </div>
          <div className="p-3 bg-cyan-500/10 rounded-xl border border-cyan-500/20 text-cyan-400">
            <Hash className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-card p-5 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-400">Malicious C2 Domains</p>
            <h3 className="text-3xl font-bold font-mono text-indigo-400 mt-1">{stats.domains_count}</h3>
            <p className="text-xs text-slate-500 mt-1">DGA, Fast Flux, Typosquatted</p>
          </div>
          <div className="p-3 bg-indigo-500/10 rounded-xl border border-indigo-500/20 text-indigo-400">
            <Globe className="w-6 h-6" />
          </div>
        </div>

        <div className="glass-card p-5 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-wider text-slate-400">Suspicious IPv4s</p>
            <h3 className="text-3xl font-bold font-mono text-rose-400 mt-1">{stats.ips_count}</h3>
            <p className="text-xs text-slate-500 mt-1">Tor Exits, Scanners, C2 Servers</p>
          </div>
          <div className="p-3 bg-rose-500/10 rounded-xl border border-rose-500/20 text-rose-400">
            <Shield className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* INSTANT IOC LOOKUP BAR */}
      <div className="glass-panel p-5">
        <h4 className="text-sm font-semibold text-white mb-2 flex items-center space-x-2">
          <Search className="w-4 h-4 text-cyan-400" />
          <span>Instant Indicator of Compromise (IOC) Verification</span>
        </h4>
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Search SHA256 hash, IP address (e.g. 185.220.101.42), or domain..."
            value={lookupQuery}
            onChange={e => setLookupQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLookup()}
            className="flex-1 bg-slate-900/60 border border-white/10 rounded-xl px-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
          <button
            onClick={handleLookup}
            className="px-5 py-2 rounded-xl text-xs font-semibold bg-cyan-500 text-slate-950 hover:bg-cyan-400 transition-all"
          >
            Verify IOC
          </button>
        </div>

        {/* Live Lookup Result Banner */}
        {lookupResult && (
          <div className={`mt-3 p-3.5 rounded-xl border transition-all ${
            lookupResult.found
              ? 'bg-rose-500/15 border-rose-500/30 text-rose-300'
              : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
          }`}>
            {lookupResult.found ? (
              <div className="flex items-center space-x-2 text-xs">
                <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0" />
                <div>
                  <span className="font-bold text-rose-400 font-mono">MATCH DETECTED:</span> {lookupResult.type} — Threat: <span className="font-semibold">{lookupResult.item?.threat}</span> ({lookupResult.item?.severity})
                </div>
              </div>
            ) : (
              <div className="flex items-center space-x-2 text-xs">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                <span>No active match found in current NetraShield IOC store. Indicator appears clean.</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ADD IOC FORM & ACTIVE WATCHLIST */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Add Form */}
        <div className="lg:col-span-4 glass-panel p-5">
          <h4 className="text-white font-semibold mb-4 flex items-center space-x-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            <span>Add New Threat Indicator</span>
          </h4>
          <form onSubmit={handleAddIoc} className="space-y-3 text-xs">
            <div>
              <label className="text-slate-400 block mb-1">Indicator Type</label>
              <select
                value={newType}
                onChange={e => setNewType(e.target.value as any)}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
              >
                <option value="sha256">SHA256 File Signature</option>
                <option value="ips">IPv4 Address</option>
                <option value="domains">Domain / Hostname</option>
              </select>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Indicator Value</label>
              <input
                type="text"
                placeholder={newType === 'ips' ? '185.220.101.42' : newType === 'domains' ? 'malicious-domain.com' : '64-char sha256'}
                value={newValue}
                onChange={e => setNewValue(e.target.value)}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-400"
                required
              />
            </div>

            <div>
              <label className="text-slate-400 block mb-1">Threat Title / Attribution</label>
              <input
                type="text"
                placeholder="e.g. CobaltStrike C2 Node"
                value={newThreat}
                onChange={e => setNewThreat(e.target.value)}
                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-slate-400 block mb-1">Severity</label>
                <select
                  value={newSeverity}
                  onChange={e => setNewSeverity(e.target.value)}
                  className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Tags (comma-separated)</label>
                <input
                  type="text"
                  placeholder="c2, botnet"
                  value={newTags}
                  onChange={e => setNewTags(e.target.value)}
                  className="w-full bg-slate-900 border border-white/10 rounded-xl px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                />
              </div>
            </div>

            <button
              type="submit"
              className="w-full mt-3 py-2.5 rounded-xl font-semibold text-slate-950 bg-cyan-500 hover:bg-cyan-400 transition-all shadow-cyan-glow flex items-center justify-center space-x-1.5"
            >
              <Plus className="w-4 h-4" />
              <span>Save Indicator to Intel Store</span>
            </button>
          </form>
        </div>

        {/* Right: Active Indicators Table */}
        <div className="lg:col-span-8 glass-panel p-5">
          <h4 className="text-white font-semibold mb-3 flex items-center justify-between">
            <span className="flex items-center space-x-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <span>Active Threat Intelligence Watchlist</span>
            </span>
            <span className="text-xs text-slate-400">Hot-reloads correlation engine</span>
          </h4>

          <div className="overflow-x-auto max-h-[380px]">
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-slate-400 uppercase tracking-wider border-b border-white/10 bg-slate-900/30 sticky top-0">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Indicator Value</th>
                  <th className="py-2.5 px-3">Threat Description</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {/* IPs */}
                {(iocData?.iocs.ips || []).map(ip => (
                  <tr key={ip.value} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 text-cyan-400">IP</td>
                    <td className="py-2.5 px-3 text-white font-semibold">{ip.value}</td>
                    <td className="py-2.5 px-3 text-slate-300 font-sans">{ip.threat}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {ip.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => handleDeleteIoc(ip.value, 'ips')}
                        className="text-slate-500 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}

                {/* Domains */}
                {(iocData?.iocs.domains || []).map(dom => (
                  <tr key={dom.value} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 text-indigo-400">DOMAIN</td>
                    <td className="py-2.5 px-3 text-white">{dom.value}</td>
                    <td className="py-2.5 px-3 text-slate-300 font-sans">{dom.threat}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">
                        {dom.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => handleDeleteIoc(dom.value, 'domains')}
                        className="text-slate-500 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}

                {/* Hashes */}
                {(iocData?.iocs.sha256 || []).map(h => (
                  <tr key={h.value} className="hover:bg-slate-800/40">
                    <td className="py-2.5 px-3 text-emerald-400">SHA256</td>
                    <td className="py-2.5 px-3 text-slate-300 truncate max-w-xs">{h.value}</td>
                    <td className="py-2.5 px-3 text-slate-300 font-sans">{h.threat}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {h.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => handleDeleteIoc(h.value, 'sha256')}
                        className="text-slate-500 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
