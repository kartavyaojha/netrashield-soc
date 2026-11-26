import React from 'react';
import { motion } from 'framer-motion';
import { ArrowDown, Play } from 'lucide-react';

interface BonanzaHeroProps {
  onScrollToWorkbench: () => void;
  onRunQuickDemo: () => void;
  loading: boolean;
}

export const BonanzaHero: React.FC<BonanzaHeroProps> = ({
  onScrollToWorkbench,
  onRunQuickDemo,
  loading
}) => {
  return (
    <section className="relative pt-20 pb-16 px-4 sm:px-8 max-w-6xl mx-auto text-center flex flex-col items-center">
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
        className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs text-zinc-300 mb-8"
      >
        <span className="w-2 h-2 rounded-full bg-[#FF4D2D]" />
        <span className="font-mono text-zinc-200 font-semibold">NetraShield SOC 2.4.0</span>
        <span className="text-zinc-600">•</span>
        <span>Autonomous Blue-Team Defense Workbench</span>
      </motion.div>

      <motion.h1
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, delay: 0.05 }}
        className="text-4xl sm:text-6xl md:text-7xl lg:text-8xl font-bold tracking-tighter leading-tightest text-white max-w-5xl font-grotesk"
      >
        Security operations and threat triage made <span className="text-[#FF4D2D]">instant.</span>
      </motion.h1>

      <motion.p
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, delay: 0.1 }}
        className="mt-6 text-base sm:text-xl text-zinc-400 max-w-3xl leading-relaxed font-sans"
      >
        What took hours of manual log inspection now completes in under <strong className="text-white font-semibold">3.0 seconds</strong>. Local Sigma rule compilation, Isolation Forest anomaly scoring, and MITRE ATT&CK enrichment running completely inside your perimeter.
      </motion.p>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, delay: 0.15 }}
        className="mt-10 flex flex-wrap items-center justify-center gap-4"
      >
        <button
          onClick={onScrollToWorkbench}
          className="bonanza-btn group bg-white text-slate-950 font-semibold px-7 py-3.5 text-sm flex items-center space-x-2.5 shadow-bonanza hover:bg-zinc-100"
        >
          <div className="bonanza-btn-text-roll">
            <span>Explore Workbench</span>
            <span className="text-[#FF4D2D]">Explore Workbench</span>
          </div>
          <ArrowDown className="w-4 h-4 transition-transform group-hover:translate-y-0.5" />
        </button>

        <button
          onClick={onRunQuickDemo}
          disabled={loading}
          className="bonanza-btn group bg-white/5 border border-white/10 hover:border-white/25 text-white font-medium px-6 py-3.5 text-sm flex items-center space-x-2 backdrop-blur-xl transition-all"
        >
          <Play className="w-4 h-4 text-zinc-300 fill-zinc-300/20" />
          <span>{loading ? 'Correlating Telemetry...' : 'Run Benchmark Drill'}</span>
        </button>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.2 }}
        className="mt-14 grid grid-cols-1 sm:grid-cols-3 gap-3 w-full max-w-2xl"
      >
        <div className="bg-white/[0.03] border border-white/10 rounded-2xl py-3 px-4 text-center">
          <p className="text-[11px] uppercase tracking-wider text-zinc-500 font-mono">Throughput</p>
          <p className="text-sm font-bold text-emerald-400 font-grotesk mt-0.5 tabular-nums">&lt; 3.0s / 10k Events</p>
        </div>
        <div className="bg-white/[0.03] border border-white/10 rounded-2xl py-3 px-4 text-center">
          <p className="text-[11px] uppercase tracking-wider text-zinc-500 font-mono">Detection</p>
          <p className="text-sm font-bold text-zinc-200 font-grotesk mt-0.5">Sigma + Isolation Forest</p>
        </div>
        <div className="bg-white/[0.03] border border-white/10 rounded-2xl py-3 px-4 text-center">
          <p className="text-[11px] uppercase tracking-wider text-zinc-500 font-mono">Telemetry</p>
          <p className="text-sm font-bold text-zinc-200 font-grotesk mt-0.5">Local Enclave Only</p>
        </div>
      </motion.div>
    </section>
  );
};
