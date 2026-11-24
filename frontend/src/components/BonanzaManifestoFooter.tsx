import React from 'react';
import { Shield, ArrowUp, Heart, Code2 } from 'lucide-react';

export const BonanzaManifestoFooter: React.FC = () => {
  const principles = [
    {
      num: '01',
      title: 'Zero Cloud Leakage',
      desc: 'All Sigma evaluation, Isolation Forest inference, and SQLite persistence run 100% locally in your offline security enclave.'
    },
    {
      num: '02',
      title: 'Hybrid Precision',
      desc: 'Sigma rules catch known attacker tactics with pinpoint accuracy. Isolation Forest catches novel zero-day obfuscation.'
    },
    {
      num: '03',
      title: 'Sub-3s Triage',
      desc: 'Vectorized NumPy math and lightweight multi-threaded sockets ensure 10,000 events are parsed and prioritized in milliseconds.'
    }
  ];

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <footer id="manifesto" className="pt-20 pb-12 border-t border-white/10 bg-[#06080F] text-slate-400">
      <div className="max-w-7xl mx-auto px-4 sm:px-8">
        {/* 3 Principles Horizontal Strip (Mirroring Bonanza's Manifesto) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pb-16 border-b border-white/10">
          {principles.map(p => (
            <div key={p.num} className="space-y-3">
              <span className="text-xs font-mono text-cyan-400 font-bold">{p.num} / PRINCIPLE</span>
              <h4 className="text-xl font-bold text-white font-grotesk tracking-tight">{p.title}</h4>
              <p className="text-xs sm:text-sm text-slate-400 leading-relaxed font-sans">{p.desc}</p>
            </div>
          ))}
        </div>

        {/* Multi-Column Editorial Footer */}
        <div className="py-12 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-8 text-xs">
          <div>
            <div className="flex items-center space-x-2 text-white font-bold font-grotesk text-sm mb-3">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span>NetraShield SOC 2.4.0</span>
            </div>
            <p className="text-slate-500 leading-relaxed font-sans">
              Autonomous blue-team cyber defense and threat correlation engine. Designed for mission-critical security operations centers.
            </p>
          </div>

          <div>
            <p className="text-white font-semibold font-grotesk mb-3">Core Modules</p>
            <ul className="space-y-2 font-mono text-slate-400">
              <li>ECS Normalizer Engine</li>
              <li>Sigma Rule Compiler (YAML)</li>
              <li>IsolationForest ML Outlier</li>
              <li>UDP/TCP Syslog Server (5140)</li>
            </ul>
          </div>

          <div>
            <p className="text-white font-semibold font-grotesk mb-3">Standards & Intel</p>
            <ul className="space-y-2 font-mono text-slate-400">
              <li>MITRE ATT&CK Matrix</li>
              <li>Elastic Common Schema</li>
              <li>Shannon Entropy Analysis</li>
              <li>SQLite Incident Store</li>
            </ul>
          </div>

          <div className="flex flex-col justify-between">
            <div>
              <p className="text-white font-semibold font-grotesk mb-3">Author</p>
              <p className="text-slate-300 font-medium">Kartavya Ojha</p>
              <p className="text-slate-500 mt-1">Autonomous Blue-Team Security Architect</p>
            </div>
            <button
              onClick={scrollToTop}
              className="mt-6 inline-flex items-center space-x-2 text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              <span>Back to Top</span>
              <ArrowUp className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Bottom Copyright */}
        <div className="pt-8 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-500 font-mono gap-3">
          <div>
            © 2026 Kartavya's NetraShield SOC 2.4.0 · All rights reserved.
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-emerald-400 flex items-center space-x-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>100% Local Sandboxed Engine</span>
            </span>
            <span>FastAPI + Vite + React + Tailwind</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
