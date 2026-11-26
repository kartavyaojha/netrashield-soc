import React from 'react';
import { Shield, ArrowUp } from 'lucide-react';

export const BonanzaManifestoFooter: React.FC = () => {
  const principles = [
    {
      num: '01',
      title: 'Perimeter Enclave',
      desc: 'All Sigma evaluation, Isolation Forest inference, and SQLite persistence execute locally within your isolated security enclave.'
    },
    {
      num: '02',
      title: 'Hybrid Precision',
      desc: 'Deterministic Sigma rules flag known tactics with pinpoint accuracy. Unsupervised Isolation Forest isolates novel, packed anomalies.'
    },
    {
      num: '03',
      title: 'Sub-3s Throughput',
      desc: 'Vectorized NumPy mathematical operations and multi-threaded sockets process 10,000 events in milliseconds without external queues.'
    }
  ];

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <footer id="manifesto" className="pt-20 pb-12 border-t border-white/10 bg-[#07060D] text-zinc-400">
      <div className="max-w-7xl mx-auto px-4 sm:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pb-16 border-b border-white/10">
          {principles.map(p => (
            <div key={p.num} className="space-y-3">
              <span className="text-xs font-mono text-zinc-500 font-bold">{p.num} / ARCHITECTURE</span>
              <h4 className="text-xl font-bold text-white font-grotesk tracking-tight">{p.title}</h4>
              <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed font-sans">{p.desc}</p>
            </div>
          ))}
        </div>

        <div className="py-12 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-8 text-xs">
          <div>
            <div className="flex items-center space-x-2 text-white font-bold font-grotesk text-sm mb-3">
              <Shield className="w-4 h-4 text-zinc-300" />
              <span>NetraShield SOC 2.4.0</span>
            </div>
            <p className="text-zinc-500 leading-relaxed font-sans">
              Local cyber defense and telemetry correlation engine. Built for high-throughput security operations.
            </p>
          </div>

          <div>
            <p className="text-white font-semibold font-grotesk mb-3">Core Modules</p>
            <ul className="space-y-2 font-mono text-zinc-400">
              <li>ECS Normalizer Engine</li>
              <li>Sigma Rule Compiler (YAML)</li>
              <li>IsolationForest Anomaly Detector</li>
              <li>UDP/TCP Syslog Server (5140)</li>
            </ul>
          </div>

          <div>
            <p className="text-white font-semibold font-grotesk mb-3">Detection Frameworks</p>
            <ul className="space-y-2 font-mono text-zinc-400">
              <li>MITRE ATT&CK Enterprise</li>
              <li>Elastic Common Schema</li>
              <li>Shannon Entropy Analysis</li>
              <li>SQLite Incident Store</li>
            </ul>
          </div>

          <div>
            <p className="text-white font-semibold font-grotesk mb-3">Stack</p>
            <p className="text-zinc-500 leading-relaxed font-sans mb-3">
              FastAPI backend, Scikit-Learn vectorization, and Vite/React workbench.
            </p>
            <button
              onClick={scrollToTop}
              className="inline-flex items-center space-x-1.5 text-xs text-zinc-300 hover:text-white transition-colors font-mono"
            >
              <span>Back to Top</span>
              <ArrowUp className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        <div className="pt-8 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between text-[11px] text-zinc-500 font-mono gap-4">
          <div>
            <span>© {new Date().getFullYear()} NetraShield SOC. Open Source Blue Team Workbench.</span>
          </div>
          <div className="flex items-center space-x-1">
            <span>Maintained by Kartavya Ojha · MIT License</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
