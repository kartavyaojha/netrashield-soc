import React from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, Cpu, Radio, CheckCircle, ArrowUpRight } from 'lucide-react';

export const BonanzaCoreCards: React.FC = () => {
  const cards = [
    {
      step: '01',
      title: 'Deterministic Sigma Engine',
      category: 'Signature Defense',
      description: 'Zero-latency YAML rule compilation evaluating process trees, command-line arguments, parent executables, and network flows against known adversary patterns.',
      icon: ShieldAlert,
      badge: 'NS-SIG-1001..1004',
      accentColor: 'text-cyan-400',
      borderColor: 'hover:border-cyan-500/40',
      bullets: [
        'Pre-compiled regex & string condition evaluators',
        'Direct mapping to MITRE Tactics & Techniques',
        'Hot-reloadable rule repository without server restarts'
      ]
    },
    {
      step: '02',
      title: 'Isolation Forest ML Detector',
      category: 'Behavioral Outliers',
      description: 'Unsupervised ensemble decision trees trained on normal telemetry baseline to identify novel, obfuscated, and packed adversary executions without hardcoded signatures.',
      icon: Cpu,
      badge: 'Scikit-Learn Ensemble',
      accentColor: 'text-indigo-400',
      borderColor: 'hover:border-indigo-500/40',
      bullets: [
        'Shannon entropy math (H > 4.2 flags Base64 encoding)',
        '4D feature vector [len, entropy, depth, port]',
        'Dynamic contamination tuner with one-click retrain'
      ]
    },
    {
      step: '03',
      title: 'Offline IOC & Live Syslog',
      category: 'Real-Time Edge',
      description: 'High-speed local indicators of compromise (SHA256, IPv4, C2 Domains) combined with a multi-threaded UDP/TCP RFC-5424 socket listener on Port 5140.',
      icon: Radio,
      badge: 'Port 5140 Stream',
      accentColor: 'text-emerald-400',
      borderColor: 'hover:border-emerald-500/40',
      bullets: [
        'Instant O(1) hash & IP lookup against intel stores',
        'Direct WebSocket real-time event streaming',
        'Attack burst simulator for automated SOC drills'
      ]
    }
  ];

  return (
    <section id="core-engine" className="py-20 px-4 sm:px-8 max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-cyan-400 mb-2">Core Architecture</p>
          <h2 className="text-3xl sm:text-5xl font-bold tracking-tight text-white font-grotesk">
            How NetraShield Defends
          </h2>
        </div>
        <p className="mt-3 md:mt-0 text-sm text-slate-400 max-w-md font-sans">
          Three decoupled, high-throughput defense layers fused into one unified risk score.
        </p>
      </div>

      {/* 3-Column Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {cards.map((card, i) => {
          const Icon = card.icon;
          return (
            <motion.div
              key={card.step}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.15 }}
              className={`bonanza-card p-6 sm:p-8 flex flex-col justify-between ${card.borderColor} group`}
            >
              <div>
                <div className="flex items-center justify-between mb-6">
                  <span className="text-xs font-mono text-slate-500 font-bold">{card.step}</span>
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-white/5 border border-white/10 text-slate-300">
                    {card.badge}
                  </span>
                </div>

                <div className="p-3 w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/10 flex items-center justify-center mb-5 group-hover:scale-105 transition-transform">
                  <Icon className={`w-6 h-6 ${card.accentColor}`} />
                </div>

                <p className="text-xs uppercase tracking-wider text-slate-400 font-mono mb-1">{card.category}</p>
                <h3 className="text-xl font-bold text-white font-grotesk tracking-tight mb-3">
                  {card.title}
                </h3>
                <p className="text-xs sm:text-sm text-slate-400 leading-relaxed font-sans mb-6">
                  {card.description}
                </p>
              </div>

              <div className="pt-6 border-t border-white/5 space-y-2.5">
                {card.bullets.map((bullet, idx) => (
                  <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300">
                    <CheckCircle className={`w-3.5 h-3.5 ${card.accentColor} shrink-0 mt-0.5`} />
                    <span>{bullet}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          );
        })}
      </div>
    </section>
  );
};
