import React from 'react';
import { motion } from 'framer-motion';
import { Zap, ShieldCheck, Cpu, ArrowDown, Play } from 'lucide-react';

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
      {/* Top Micro-Badge */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs text-slate-300 mb-8 backdrop-blur-md"
      >
        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
        <span className="font-mono text-cyan-300">NetraShield SOC 2.4.0</span>
        <span className="text-slate-500">•</span>
        <span>Kartavya's Autonomous Blue-Team Architecture</span>
      </motion.div>

      {/* Massive Tight-Tracked Grotesque Headline */}
      <motion.h1
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.1 }}
        className="text-4xl sm:text-6xl md:text-7xl lg:text-8xl font-bold tracking-tighter leading-tightest text-white max-w-5xl font-grotesk"
      >
        The blue-team workbench that makes threat triage <span className="bg-gradient-to-r from-blue-400 via-cyan-300 to-emerald-400 bg-clip-text text-transparent">instant.</span>
      </motion.h1>

      {/* Crisp 2-line Subheadline */}
      <motion.p
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="mt-6 text-base sm:text-xl text-slate-400 max-w-3xl leading-relaxed font-sans"
      >
        What took hours of manual log grep now takes under <strong className="text-white font-semibold">3 seconds</strong>. Sigma rules, Isolation Forest anomaly scoring, and MITRE ATT&CK enrichment—running <strong className="text-white font-semibold">100% locally</strong> in your sandbox.
      </motion.p>

      {/* CTA Buttons */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.3 }}
        className="mt-10 flex flex-wrap items-center justify-center gap-4"
      >
        <button
          onClick={onScrollToWorkbench}
          className="bonanza-btn group bg-white text-slate-950 font-semibold px-7 py-3.5 text-sm flex items-center space-x-2.5 shadow-bonanza hover:bg-slate-100"
        >
          <div className="bonanza-btn-text-roll">
            <span>Explore Interactive Workbench</span>
            <span className="text-blue-600">Explore Interactive Workbench</span>
          </div>
          <ArrowDown className="w-4 h-4 transition-transform group-hover:translate-y-0.5" />
        </button>

        <button
          onClick={onRunQuickDemo}
          disabled={loading}
          className="bonanza-btn group bg-white/5 border border-white/10 hover:border-white/25 text-white font-medium px-6 py-3.5 text-sm flex items-center space-x-2 backdrop-blur-xl transition-all"
        >
          <Play className="w-4 h-4 text-cyan-400 fill-cyan-400/30" />
          <span>{loading ? 'Correlating Telemetry...' : 'Run Attack Telemetry Demo'}</span>
        </button>
      </motion.div>

      {/* 3 Metric Pills */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.7, delay: 0.4 }}
        className="mt-14 grid grid-cols-1 sm:grid-cols-3 gap-3 w-full max-w-2xl"
      >
        <div className="bg-white/[0.03] border border-white/5 rounded-2xl py-2.5 px-4 text-center">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 font-mono">Benchmark</p>
          <p className="text-sm font-bold text-emerald-400 font-grotesk mt-0.5">&lt; 3.0s on 10k Events</p>
        </div>
        <div className="bg-white/[0.03] border border-white/5 rounded-2xl py-2.5 px-4 text-center">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 font-mono">Detection</p>
          <p className="text-sm font-bold text-cyan-300 font-grotesk mt-0.5">Sigma + Isolation Forest</p>
        </div>
        <div className="bg-white/[0.03] border border-white/5 rounded-2xl py-2.5 px-4 text-center">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 font-mono">Privacy</p>
          <p className="text-sm font-bold text-indigo-300 font-grotesk mt-0.5">Zero Cloud Telemetry Leak</p>
        </div>
      </motion.div>
    </section>
  );
};
