import React from 'react';
import { Shield, Cpu, Activity, Terminal, Database, Lock, Code2, Server } from 'lucide-react';

export const BonanzaMarquee: React.FC = () => {
  const capabilities = [
    { label: 'Windows Sysmon EID 1/3', icon: Shield },
    { label: 'Elastic Common Schema (ECS)', icon: Database },
    { label: 'SigmaHQ YAML Detection', icon: Code2 },
    { label: 'MITRE ATT&CK Enterprise', icon: Activity },
    { label: 'Scikit-Learn IsolationForest', icon: Cpu },
    { label: 'Scapy PCAP Inspection', icon: Terminal },
    { label: 'RFC-5424 Syslog UDP 5140', icon: Server },
    { label: 'FastAPI REST & WebSockets', icon: Lock },
    { label: 'SQLite Incident Storage', icon: Database },
  ];

  return (
    <section className="py-12 border-y border-white/5 bg-[#0A0D15]/60 overflow-hidden relative">
      <div className="max-w-7xl mx-auto px-4 mb-4 text-center">
        <p className="text-xs uppercase tracking-widest text-zinc-500 font-mono">
          Engineered on Open Telemetry & Security Standards
        </p>
      </div>

      <div className="relative flex overflow-x-hidden">
        <div className="animate-marquee flex items-center space-x-8 py-2">
          {[...capabilities, ...capabilities].map((item, idx) => {
            const Icon = item.icon;
            return (
              <div
                key={idx}
                className="flex items-center space-x-2.5 px-4 py-2 rounded-full bg-white/[0.03] border border-white/10 text-zinc-300 font-mono text-xs whitespace-nowrap hover:border-white/25 hover:text-white transition-all shadow-sm"
              >
                <Icon className="w-3.5 h-3.5 text-zinc-400 opacity-80" />
                <span>{item.label}</span>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
