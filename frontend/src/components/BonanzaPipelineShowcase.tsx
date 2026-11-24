import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileText,
  Binary,
  Layers,
  ShieldCheck,
  ChevronRight,
  ArrowRight,
  Sparkles,
  Lock,
  RotateCw,
  Maximize2
} from 'lucide-react';
import { EmbeddedSocWorkbench } from './EmbeddedSocWorkbench';
import type { TriageResult, IncidentStatus } from '../types/soc';

interface BonanzaPipelineShowcaseProps {
  triageData: TriageResult | null;
  loading: boolean;
  onRunTriage: (fd: FormData) => void;
  onUpdateStatus: (alertId: string, newStatus: IncidentStatus) => void;
  onToggleFullScreen: () => void;
}

export const BonanzaPipelineShowcase: React.FC<BonanzaPipelineShowcaseProps> = ({
  triageData,
  loading,
  onRunTriage,
  onUpdateStatus,
  onToggleFullScreen
}) => {
  const [activeStep, setActiveStep] = useState<number>(4);

  const steps = [
    { num: '01', title: 'Raw Telemetry', subtitle: 'Multi-format logs' },
    { num: '02', title: 'ECS Normalize', subtitle: 'Standardization & Entropy' },
    { num: '03', title: 'Sigma & ML Correlate', subtitle: 'Hybrid Risk Fusion' },
    { num: '04', title: 'Live Triage Workbench', subtitle: 'Fully Functional SOC App' },
  ];

  return (
    <section id="pipeline-showcase" className="py-16 px-4 sm:px-8 max-w-7xl mx-auto w-full">
      {/* Section Header */}
      <div className="text-center mb-10 max-w-3xl mx-auto">
        <p className="text-xs font-mono uppercase tracking-widest text-cyan-400 mb-2">Detection Pipeline</p>
        <h2 className="text-3xl sm:text-5xl font-bold tracking-tight text-white font-grotesk">
          From chaotic logs to correlated incident response in <span className="text-cyan-300">&lt; 3.0s</span>
        </h2>
        <p className="mt-3 text-sm sm:text-base text-slate-400 font-sans">
          Follow the autonomous 4-phase correlation flow, or jump directly into the live embedded workbench below.
        </p>
      </div>

      {/* Interactive 4-Step Selector Bar (Signature Bonanza Layout) */}
      <div className="bg-[#0B0E17]/90 border border-white/10 rounded-2xl p-1.5 sm:p-2 mb-8 backdrop-blur-xl max-w-4xl mx-auto shadow-bonanza">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-1.5">
          {steps.map(s => {
            const stepNum = parseInt(s.num);
            const isActive = activeStep === stepNum;
            return (
              <button
                key={s.num}
                onClick={() => setActiveStep(stepNum)}
                className={`relative px-4 py-3 rounded-xl text-left transition-all ${
                  isActive ? 'text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="pipeline-active-pill"
                    className="absolute inset-0 bg-gradient-to-r from-blue-600/30 via-indigo-600/20 to-cyan-500/20 border border-cyan-400/40 rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.15)]"
                    transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                  />
                )}
                <div className="relative z-10 flex flex-col">
                  <div className="flex items-center justify-between">
                    <span className={`text-[10px] font-mono ${isActive ? 'text-cyan-400 font-bold' : 'text-slate-500'}`}>
                      {s.num}
                    </span>
                    {isActive && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />}
                  </div>
                  <span className="text-xs sm:text-sm font-semibold tracking-tight font-grotesk mt-0.5">
                    {s.title}
                  </span>
                  <span className="text-[10px] text-slate-500 truncate mt-0.5 hidden sm:block">
                    {s.subtitle}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Dynamic Step Content Showcase */}
      <AnimatePresence mode="wait">
        {activeStep === 1 && (
          <motion.div
            key="step-1"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.3 }}
            className="bonanza-card p-6 sm:p-8 max-w-4xl mx-auto mb-10"
          >
            <div className="flex flex-col md:flex-row gap-6 items-start justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">Phase 01 Telemetry Ingestion</span>
                <h3 className="text-2xl font-bold text-white font-grotesk mt-1">Multi-Vendor Raw Log Parser</h3>
                <p className="text-xs text-slate-400 mt-2 max-w-xl leading-relaxed">
                  NetraShield ingests Windows Sysmon EVTX, Linux RFC-5424 Syslog, Raw PCAP network frames, and structured JSON/CSV telemetry with zero external cloud dependencies.
                </p>
                <div className="mt-4 flex flex-wrap gap-2 text-xs font-mono">
                  {['.json', '.csv', '.evtx', '.pcap', '.syslog', 'UDP 5140'].map(fmt => (
                    <span key={fmt} className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300">
                      {fmt}
                    </span>
                  ))}
                </div>
              </div>
              <button
                onClick={() => setActiveStep(4)}
                className="px-5 py-2.5 rounded-full bg-cyan-500 text-slate-950 font-semibold text-xs flex items-center space-x-2 shrink-0 hover:bg-cyan-400 transition-colors shadow-pill"
              >
                <span>Jump to Live Triage</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
            <div className="mt-6 p-4 rounded-xl bg-[#07090E] border border-white/5 font-mono text-xs text-cyan-300 overflow-x-auto">
              <span className="text-slate-500">// Example Ingested Sysmon Event (Encoded PowerShell)</span>
              <br />
              {`{"EventID": 1, "Image": "powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3...", "DestinationIp": "185.220.101.42", "DestinationPort": 8080}`}
            </div>
          </motion.div>
        )}

        {activeStep === 2 && (
          <motion.div
            key="step-2"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.3 }}
            className="bonanza-card p-6 sm:p-8 max-w-4xl mx-auto mb-10"
          >
            <div className="flex flex-col md:flex-row gap-6 items-start justify-between">
              <div>
                <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider">Phase 02 Normalization</span>
                <h3 className="text-2xl font-bold text-white font-grotesk mt-1">ECS Mapper & Shannon Entropy Math</h3>
                <p className="text-xs text-slate-400 mt-2 max-w-xl leading-relaxed">
                  Disparate vendor schemas are normalized into Elastic Common Schema (ECS) standard fields. Simultaneously, command strings are evaluated with Shannon entropy:
                </p>
                <div className="mt-3 p-3 rounded-xl bg-white/5 border border-white/10 font-mono text-xs text-emerald-300 inline-block">
                  H(X) = - ∑ (p_i · log₂ p_i) &nbsp;·&nbsp; Benign &lt; 3.6 | Obfuscated &gt; 4.2
                </div>
              </div>
              <button
                onClick={() => setActiveStep(4)}
                className="px-5 py-2.5 rounded-full bg-emerald-500 text-slate-950 font-semibold text-xs flex items-center space-x-2 shrink-0 hover:bg-emerald-400 transition-colors shadow-pill"
              >
                <span>Jump to Live Triage</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </motion.div>
        )}

        {activeStep === 3 && (
          <motion.div
            key="step-3"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            transition={{ duration: 0.3 }}
            className="bonanza-card p-6 sm:p-8 max-w-4xl mx-auto mb-10"
          >
            <div className="flex flex-col md:flex-row gap-6 items-start justify-between">
              <div>
                <span className="text-xs font-mono text-indigo-400 uppercase tracking-wider">Phase 03 Correlation</span>
                <h3 className="text-2xl font-bold text-white font-grotesk mt-1">Hybrid Risk Fusion (Sigma + ML + IOC)</h3>
                <p className="text-xs text-slate-400 mt-2 max-w-xl leading-relaxed">
                  Sigma rules match known tactics (`T1059.001`, `T1003.001`). Isolation Forest evaluates unseen anomaly feature vectors `[cmd_len, entropy, depth, port]`.
                </p>
                <div className="mt-3 p-3 rounded-xl bg-white/5 border border-white/10 font-mono text-xs text-indigo-300 inline-block">
                  risk = max(ml_score, 78.0 + 6.0 * rules) &nbsp;·&nbsp; IOC Floor: 92.0 &nbsp;·&nbsp; Capped: 99.9
                </div>
              </div>
              <button
                onClick={() => setActiveStep(4)}
                className="px-5 py-2.5 rounded-full bg-indigo-500 text-white font-semibold text-xs flex items-center space-x-2 shrink-0 hover:bg-indigo-400 transition-colors shadow-pill"
              >
                <span>Jump to Live Triage</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* EMBEDDED LIVE PRODUCT FRAME (Signature Bonanza revenue.yourcompany.app Style) */}
      <div className="bonanza-card p-3 sm:p-4 border border-white/15 shadow-bonanza relative overflow-hidden">
        {/* Browser Top Window Chrome */}
        <div className="bg-[#07090E]/90 px-4 py-2.5 rounded-t-xl border-b border-white/10 flex items-center justify-between">
          {/* Traffic light dots */}
          <div className="flex items-center space-x-2">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>

          {/* URL Bar */}
          <div className="flex items-center space-x-2 px-4 py-1 rounded-full bg-slate-900/80 border border-white/10 text-xs font-mono text-slate-400 w-full max-w-md justify-center">
            <Lock className="w-3 h-3 text-emerald-400 shrink-0" />
            <span className="text-slate-200">https://netrashield.local</span>
            <span className="text-slate-500">/triage</span>
          </div>

          {/* Window action */}
          <div className="flex items-center space-x-2 text-slate-400">
            <button
              onClick={onToggleFullScreen}
              className="p-1.5 rounded hover:bg-white/5 hover:text-white transition-colors"
              title="Expand to Full-Screen Workbench"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Embedded Working Application */}
        <div className="bg-[#050811] rounded-b-xl overflow-hidden pt-2">
          <EmbeddedSocWorkbench
            triageData={triageData}
            loading={loading}
            onRunTriage={onRunTriage}
            onUpdateStatus={onUpdateStatus}
            onToggleFullScreen={onToggleFullScreen}
          />
        </div>
      </div>
    </section>
  );
};
