import React from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, Zap, Terminal, Globe, Lock, ArrowUpRight } from 'lucide-react';

export const BonanzaBentoGrid: React.FC = () => {
  return (
    <section id="bento-coverage" className="py-20 px-4 sm:px-8 max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="text-center mb-12 max-w-3xl mx-auto">
        <p className="text-xs font-mono uppercase tracking-widest text-cyan-400 mb-2">Detection Benchmarks</p>
        <h2 className="text-3xl sm:text-5xl font-bold tracking-tight text-white font-grotesk">
          Proven Under Heavy Fire
        </h2>
        <p className="mt-3 text-sm text-slate-400 font-sans">
          Real incident scenarios detected with sub-second hybrid precision across multiple threat vectors.
        </p>
      </div>

      {/* Asymmetric Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
        {/* Card 1: 10,000 Events Benchmark (Large Spanning Card) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="md:col-span-8 bonanza-card p-6 sm:p-8 flex flex-col justify-between border-emerald-500/20 hover:border-emerald-500/40"
        >
          <div className="flex items-center justify-between mb-4">
            <span className="px-3 py-1 rounded-full text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              Throughput Benchmark
            </span>
            <span className="text-xs font-mono text-slate-500">Vectorized ML Inference</span>
          </div>

          <div>
            <div className="flex items-baseline space-x-3 mb-2">
              <span className="text-5xl sm:text-7xl font-bold text-white font-mono tracking-tighter">0.33s</span>
              <span className="text-slate-400 text-lg font-mono">/ 10,000 events</span>
            </div>
            <h4 className="text-xl font-bold text-white font-grotesk mt-2">
              High-Velocity Batch Processing
            </h4>
            <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-xl font-sans">
              Evaluates 10,000 simultaneous telemetry records through feature matrix vectorization, Shannon entropy calculation, and IsolationForest decision functions in less than half a second.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-white/5 flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400">
            <span>Passes strict &lt; 3000ms SLA</span>
            <span>•</span>
            <span className="text-emerald-400 font-semibold">100% In-Memory NumPy / Scikit-Learn</span>
          </div>
        </motion.div>

        {/* Card 2: Encoded PowerShell (T1059.001) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.1 }}
          className="md:col-span-4 bonanza-card p-6 sm:p-8 flex flex-col justify-between border-rose-500/20 hover:border-rose-500/40"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">
                T1059.001
              </span>
              <span className="text-xs font-mono text-rose-400 font-bold">94.2 RISK</span>
            </div>
            <h4 className="text-lg font-bold text-white font-grotesk">Encoded PowerShell Execution</h4>
            <p className="text-xs text-slate-400 mt-2 font-sans">
              Catches Base64 encoded download cradles via dual triggers: Sigma rule `NS-SIG-1001` + Shannon entropy H &gt; 4.2.
            </p>
          </div>
          <div className="mt-6 p-2.5 rounded-xl bg-slate-950 border border-white/5 font-mono text-[11px] text-cyan-300 truncate">
            powershell.exe -enc SQBFAFgAIAAoAE4AZQ...
          </div>
        </motion.div>

        {/* Card 3: LSASS Memory Dump (T1003.001) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.2 }}
          className="md:col-span-4 bonanza-card p-6 sm:p-8 flex flex-col justify-between border-amber-500/20 hover:border-amber-500/40"
        >
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/30">
                T1003.001
              </span>
              <span className="text-xs font-mono text-amber-400 font-bold">89.7 RISK</span>
            </div>
            <h4 className="text-lg font-bold text-white font-grotesk">LSASS Credential Access</h4>
            <p className="text-xs text-slate-400 mt-2 font-sans">
              Flags Procdump, Sekurlsa, and Comsvcs MiniDump attempts with instant incident escalation and SQLite audit persistence.
            </p>
          </div>
          <div className="mt-6 p-2.5 rounded-xl bg-slate-950 border border-white/5 font-mono text-[11px] text-amber-300 truncate">
            procdump.exe -ma lsass.exe C:\Temp\lsass.dmp
          </div>
        </motion.div>

        {/* Card 4: C2 Beaconing IOC (T1071.001) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.3 }}
          className="md:col-span-8 bonanza-card p-6 sm:p-8 flex flex-col justify-between border-cyan-500/20 hover:border-cyan-500/40"
        >
          <div className="flex items-center justify-between mb-4">
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              T1071.001
            </span>
            <span className="text-xs font-mono text-cyan-400 font-bold">92.0+ RISK (IOC FLOOR)</span>
          </div>

          <div>
            <div className="flex items-baseline space-x-2">
              <span className="text-3xl sm:text-5xl font-bold text-cyan-300 font-mono">185.220.101.42</span>
            </div>
            <h4 className="text-xl font-bold text-white font-grotesk mt-2">
              DarkHydrus / Tor Exit Node C2 Correlated
            </h4>
            <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-xl font-sans">
              Instant indicator matching from local threat intel stores elevates any outbound beaconing event directly to CRITICAL status with zero external network queries.
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-white/5 flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400">
            <span>intel/ioc_store.json Watchlist</span>
            <span>•</span>
            <span className="text-cyan-400">Hot-reloaded in memory</span>
          </div>
        </motion.div>
      </div>
    </section>
  );
};
