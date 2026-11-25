import React, { useState } from 'react';
import { Shield, LayoutGrid, ArrowUpRight, Volume2, VolumeX } from 'lucide-react';
import { sound } from '../utils/audio';

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
  const [audioMuted, setAudioMuted] = useState(false);

  const toggleAudio = () => {
    const next = !audioMuted;
    setAudioMuted(next);
    sound.enabled = !next;
    if (!next) {
      sound.playTick();
    }
  };

  return (
    <header className="sticky top-4 z-50 px-4 sm:px-8 max-w-7xl mx-auto w-full transition-all">
      <div className="bg-[#12111B]/95 border border-white/10 rounded-full px-5 py-3 flex items-center justify-between shadow-pill backdrop-blur-xl">
        {/* Left: Brand Wordmark */}
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-indigo-600 via-violet-500 to-purple-400 p-[1px] flex items-center justify-center">
            <div className="w-full h-full bg-[#09090F] rounded-full flex items-center justify-center text-violet-400">
              <Shield className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <span className="font-bold text-sm tracking-tight text-white font-grotesk">NetraShield SOC</span>
            <span className="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-white/5 border border-white/10 text-zinc-300">
              <span className={`w-1.5 h-1.5 rounded-full ${engineOnline ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
              <span>v2.4.0 · {engineOnline ? 'Engine Online' : 'Engine Ready'}</span>
            </span>
          </div>
        </div>

        {/* Center: Minimal Navigation Links (Desktop) */}
        {!fullScreenWorkbench && (
          <nav className="hidden md:flex items-center space-x-7 text-xs font-medium text-zinc-400">
            <a href="#pipeline-showcase" className="hover:text-white transition-colors">Workbench</a>
            <a href="#core-engine" className="hover:text-white transition-colors">Detection Engine</a>
            <a href="#bento-coverage" className="hover:text-white transition-colors">MITRE Coverage</a>
            <a href="#manifesto" className="hover:text-white transition-colors">Architecture</a>
          </nav>
        )}

        {/* Right: Audio Mute, Mode Toggle, and Dual-Layer Roll CTA */}
        <div className="flex items-center space-x-2.5">
          {/* Sound FX Toggle */}
          <button
            onClick={toggleAudio}
            className="p-2 rounded-full bg-white/5 hover:bg-white/10 border border-white/10 text-zinc-400 hover:text-white transition-colors"
            title={audioMuted ? 'Unmute Haptic Audio FX' : 'Mute Haptic Audio FX'}
          >
            {audioMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5 text-violet-400" />}
          </button>

          <button
            onClick={onToggleFullScreen}
            className={`px-3.5 py-1.5 rounded-full text-xs font-medium border transition-all flex items-center space-x-1.5 ${
              fullScreenWorkbench
                ? 'bg-indigo-600/20 border-indigo-500/40 text-indigo-300 shadow-[0_0_15px_rgba(99,102,241,0.2)]'
                : 'bg-white/5 border-white/10 text-zinc-300 hover:text-white hover:bg-white/10'
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
            className="bonanza-btn group bg-white text-slate-950 font-semibold px-4 sm:px-5 py-2 text-xs flex items-center space-x-2 shadow-pill hover:bg-zinc-100"
          >
            <div className="bonanza-btn-text-roll">
              <span className="font-medium text-slate-950">Launch Triage</span>
              <span className="font-medium text-indigo-600">Execute Engine</span>
            </div>
            <ArrowUpRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
