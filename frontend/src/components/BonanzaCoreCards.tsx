import React from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, Cpu, Radio } from 'lucide-react';

export const BonanzaCoreCards: React.FC = () => {
  const cards = [
    {
      step: '01',
      title: 'Deterministic Sigma Engine',
      category: 'Signature Defense',
      description: 'Zero-latency YAML rule compilation evaluating process trees, command arguments, parent executables, and network flows against known adversary patterns.',
      icon: ShieldAlert,
      badge: 'NS-SIG-1001..1004',
      accentColor: 'text-zinc-200',
      bullets: [
        'Pre-compiled regex & string condition evaluators',
        'Direct mapping to MITRE Tactics & Techniques',
        'Hot-reloadable rule repository without process restarts'
      ]
    },
    {
      step: '02',
      title: 'Isolation Forest ML Detector',
      category: 'Behavioral Outliers',
      description: 'Unsupervised ensemble decision trees trained on normal telemetry baseline to identify novel, obfuscated, and packed adversary executions without hardcoded signatures.',
      icon: Cpu,
      badge: 'Scikit-Learn Ensemble',
      accentColor: 'text-zinc-200',
      bullets: [
        'Shannon entropy math (H > 4.2 flags Base64 encoding)',
        '4D feature vector [len, entropy, depth, port]',
        'Dynamic contamination tuner with one-click retrain'
      ]
    },
    {
      step: '03',
      title: 'Offline IOC & Live Syslog',
      category: 'Real-Time Ingestion',
      description: 'High-speed local indicators of compromise (SHA256, IPv4, C2 Domains) combined with a multi-threaded UDP/TCP RFC-5424 socket listener on Port 5140.',
      icon: Radio,
      badge: 'Port 5140 Socket',
      accentColor: 'text-zinc-200',
      bullets: [
        'O(1) hash & IP lookup against local watchlist stores',
        'Direct WebSocket real-time event streaming',
        'Attack burst simulator for automated SOC drills'
      ]
    }
  ];

  return (
    <section id="core-engine" className="py-20 px-4 sm:px-8 max-w-7xl mx-auto w-full">
      <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
        <div>
          <p className="text-xs font-mono uppercase tracking-widest text-zinc-500 mb-2">Core Architecture</p>
          <h2 className="text-3xl sm:text-5xl font-bold tracking-tight text-white font-grotesk">
            Detection Architecture
          </h2>
        </div>
        <p className="mt-3 md:mt-0 text-sm text-zinc-400 max-w-md font-sans">
          Three decoupled, high-throughput defense layers fused into one unified risk score.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {cards.map((card, i) => {
          const Icon = card.icon;
          return (
            <motion.div
              key={card.step}
              initial={{ opacity: 0, y: 15 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.25, delay: i * 0.08 }}
              className="bonanza-card p-6 sm:p-8 flex flex-col justify-between hover:border-white/20 transition-all"
            >
              <div>
                <div className="flex items-center justify-between mb-6">
                  <span className="text-xs font-mono text-zinc-500 tabular-nums">{card.step} / MODULE</span>
                  <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-white/5 border border-white/10 ${card.accentColor}`}>
                    {card.badge}
                  </span>
                </div>

                <div className="mb-4">
                  <div className={`w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center ${card.accentColor} mb-3`}>
                    <Icon className="w-5 h-5 text-zinc-300" />
                  </div>
                  <span className="text-[11px] uppercase tracking-wider font-mono text-zinc-500">
                    {card.category}
                  </span>
                  <h3 className="text-xl font-bold text-white font-grotesk mt-1">
                    {card.title}
                  </h3>
                </div>

                <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed font-sans mb-6">
                  {card.description}
                </p>
              </div>

              <div className="pt-4 border-t border-white/5">
                <ul className="space-y-2">
                  {card.bullets.map((b, idx) => (
                    <li key={idx} className="flex items-center space-x-2 text-xs text-zinc-400">
                      <span className="w-1.5 h-1.5 rounded-full bg-zinc-500" />
                      <span>{b}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </motion.div>
          );
        })}
      </div>
    </section>
  );
};
