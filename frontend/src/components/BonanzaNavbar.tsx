import React from 'react';
import { Shield, Sparkles, LayoutGrid, Terminal, ArrowUpRight } from 'lucide-react';

interface BonanzaNavbarProps {
  fullScreenWorkbench: boolean;
  onToggleFullScreen: () => void;
  onLaunchTriageClick: () => void;
  engineOnline: boolean;
}

export const BonanzaNavbar: React.FC<BonanzaNavbarProps> = ({
  fullScreenWorkbench,
  onToggleFullScreen,
  onLaunchTriageClick,
  engineOnline
}) => {
  return (
    <header className="sticky top-4 z-50 px-4 sm:px-8 max-w-7xl mx-auto w-full transition-all">
      <div className="bg-[#0D111A]/80 backdrop-blur-xl border border-white/10 rounded-full px-5 py-3 flex items-center justify-between shadow-pill">
        {/* Left: Brand Wordmark */}
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-blue-600 via-indigo-500 to-cyan-400 p-[1px] flex items-center justify-center">
            <div className="w-full h-full bg-[#07090E] rounded-full flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-sm tracking-tight text-white font-grotesk">NetraShield SOC</span>
            <span className="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-white/5 border border-white/10 text-slate-300">
              <span className={`w-1.5 h-1.5 rounded-full ${engineOnline ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
              <span>v2.4.0 · {engineOnline ? 'Engine Online' : 'Engine Ready'}</span>
            </span>
          </div>
        </div>

        {/* Center: Minimal Navigation Links (Desktop) */}
        {!fullScreenWorkbench && (
          <nav className="hidden md:flex items-center space-x-7 text-xs font-medium text-slate-300">
            <a href="#pipeline-showcase" className="hover:text-white transition-colors">Workbench</a>
            <a href="#core-engine" className="hover:text-white transition-colors">Detection Engine</a>
            <a href="#bento-coverage" className="hover:text-white transition-colors">MITRE Coverage</a>
            <a href="#manifesto" className="hover:text-white transition-colors">Architecture</a>
          </nav>
        )}

        {/* Right: Dual-Layer Roll CTA & Mode Toggle */}
        <div className="flex items-center space-x-2.5">
          <button
            onClick={onToggleFullScreen}
            className={`px-3.5 py-1.5 rounded-full text-xs font-medium border transition-all flex items-center space-x-1.5 ${
              fullScreenWorkbench
                ? 'bg-cyan-500/15 border-cyan-400/40 text-cyan-300'
                : 'bg-white/5 border-white/10 text-slate-300 hover:text-white hover:bg-white/10'
            }`}
          >
            <LayoutGrid className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">
              {fullScreenWorkbench ? 'Showcase View' : 'Full Workbench'}
            </span>
          </button>

          {/* Bonanza Signature Text-Roll Button */}
          <button
            onClick={onLaunchTriageClick}
            className="bonanza-btn group bg-white text-slate-950 font-semibold px-4 sm:px-5 py-2 text-xs flex items-center space-x-2 shadow-pill hover:bg-slate-100"
          >
            <div className="bonanza-btn-text-roll">
              <span className="font-medium text-slate-950">Launch Triage</span>
              <span className="font-medium text-blue-600">Execute Engine</span>
            </div>
            <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
