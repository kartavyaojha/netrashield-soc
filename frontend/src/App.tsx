import React, { useState, useEffect, useRef } from 'react';
import { BonanzaNavbar } from './components/BonanzaNavbar';
import { BonanzaHero } from './components/BonanzaHero';
import { BonanzaPipelineShowcase } from './components/BonanzaPipelineShowcase';
import { BonanzaMarquee } from './components/BonanzaMarquee';
import { BonanzaCoreCards } from './components/BonanzaCoreCards';
import { BonanzaBentoGrid } from './components/BonanzaBentoGrid';
import { BonanzaManifestoFooter } from './components/BonanzaManifestoFooter';
import { EmbeddedSocWorkbench } from './components/EmbeddedSocWorkbench';
import { PlexusCursorCanvas } from './components/PlexusCursorCanvas';
import type { TriageResult, IncidentStatus } from './types/soc';
import { sound } from './utils/audio';

export const App: React.FC = () => {
  const [fullScreenWorkbench, setFullScreenWorkbench] = useState(false);
  const [triageData, setTriageData] = useState<TriageResult | null>(null);
  const [loadingTriage, setLoadingTriage] = useState(false);
  const [engineOnline, setEngineOnline] = useState(true);
  const spotlightRef = useRef<HTMLDivElement>(null);

  // Performance-optimized cursor spotlight: direct DOM manipulation via requestAnimationFrame
  // ZERO React component re-renders!
  useEffect(() => {
    let rafId: number | null = null;
    const handleMouseMove = (e: MouseEvent) => {
      if (rafId) return;
      rafId = requestAnimationFrame(() => {
        if (spotlightRef.current) {
          spotlightRef.current.style.transform = `translate3d(${e.clientX - 300}px, ${e.clientY - 300}px, 0)`;
        }
        rafId = null;
      });
    };
    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, []);

  // Check health and run initial triage on mount
  useEffect(() => {
    checkHealth();
    runInitialTriage();
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setEngineOnline(data.status === 'healthy');
      }
    } catch (e) {
      setEngineOnline(false);
    }
  };

  const runInitialTriage = async () => {
    try {
      setLoadingTriage(true);
      const fd = new FormData();
      fd.append('use_demo', 'true');
      fd.append('min_risk_threshold', '40');
      fd.append('contamination', '0.05');
      fd.append('worker_threads', '4');

      const res = await fetch('/api/triage/run', {
        method: 'POST',
        body: fd
      });
      if (res.ok) {
        const data = await res.json();
        setTriageData(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingTriage(false);
    }
  };

  const handleRunTriage = async (formData: FormData) => {
    try {
      setLoadingTriage(true);
      const res = await fetch('/api/triage/run', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        setTriageData(data);
        sound.playChirp();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingTriage(false);
    }
  };

  const handleUpdateStatus = async (alertId: string, newStatus: IncidentStatus) => {
    try {
      await fetch(`/api/incidents/${alertId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (triageData) {
        const updated = triageData.alerts.map(a =>
          a.alert_id === alertId ? { ...a, status: newStatus } : a
        );
        setTriageData({ ...triageData, alerts: updated });
      }
    } catch (e) {
      console.error(e);
    }
  };

  const scrollToWorkbench = () => {
    sound.playTick();
    const el = document.getElementById('pipeline-showcase');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleLaunchTriageCTA = () => {
    sound.playChirp();
    setFullScreenWorkbench(true);
    runInitialTriage();
  };

  return (
    <div className="relative min-h-screen bg-[#09090F] text-[#FAF5FF] selection:bg-indigo-600 selection:text-white flex flex-col font-sans overflow-x-hidden">
      {/* Interactive Constellation / Neural Plexus Web Cursor Animation */}
      <PlexusCursorCanvas />

      {/* Ambient Cursor Spotlight Glow */}
      <div
        ref={spotlightRef}
        className="pointer-events-none fixed top-0 left-0 w-[600px] h-[600px] rounded-full z-0 will-change-transform opacity-70"
        style={{
          background: 'radial-gradient(circle, rgba(99, 102, 241, 0.09) 0%, transparent 70%)',
          transform: 'translate3d(-9999px, -9999px, 0)'
        }}
      />

      {/* Foreground Content */}
      <div className="relative z-10 flex flex-col min-h-screen">
        {/* Sticky Minimal Navbar */}
        <BonanzaNavbar
          fullScreenWorkbench={fullScreenWorkbench}
          onToggleFullScreen={() => {
            sound.playTick();
            setFullScreenWorkbench(!fullScreenWorkbench);
          }}
          onLaunchTriageClick={handleLaunchTriageCTA}
          engineOnline={engineOnline}
        />

        {/* Main Content: Two-Mode Experience */}
        {fullScreenWorkbench ? (
          /* Full-Screen Distraction-Free Workbench Mode */
          <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 animate-in fade-in duration-200">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold font-grotesk text-white">Full-Screen Threat Operations Center</h2>
                <p className="text-xs text-slate-400 font-sans">Autonomous Blue-Team correlation, live syslog, and MITRE mapping</p>
              </div>
              <button
                onClick={() => {
                  sound.playTick();
                  setFullScreenWorkbench(false);
                }}
                className="px-4 py-2 rounded-full text-xs font-semibold bg-white/10 hover:bg-white/20 text-slate-200 transition-colors font-mono"
              >
                Exit to Product Showcase
              </button>
            </div>
            <EmbeddedSocWorkbench
              triageData={triageData}
              loading={loadingTriage}
              onRunTriage={handleRunTriage}
              onUpdateStatus={handleUpdateStatus}
              isFullScreen={true}
              onToggleFullScreen={() => {
                sound.playTick();
                setFullScreenWorkbench(false);
              }}
            />
          </main>
        ) : (
          /* Bonanza-Style Showcase Mode */
          <main className="flex-1 flex flex-col">
            {/* Section 2: Editorial Hero */}
            <BonanzaHero
              onScrollToWorkbench={scrollToWorkbench}
              onRunQuickDemo={() => {
                sound.playTick();
                runInitialTriage();
              }}
              loading={loadingTriage}
            />

            {/* Section 3: Interactive 4-Step Pipeline + Embedded Live Product Frame */}
            <BonanzaPipelineShowcase
              triageData={triageData}
              loading={loadingTriage}
              onRunTriage={handleRunTriage}
              onUpdateStatus={handleUpdateStatus}
              onToggleFullScreen={() => {
                sound.playTick();
                setFullScreenWorkbench(true);
              }}
            />

            {/* Section 4: Infinite Scrolling Marquee */}
            <BonanzaMarquee />

            {/* Section 5: 3-Column Core Engine Cards */}
            <BonanzaCoreCards />

            {/* Section 6: Bento Detection Showcase Grid */}
            <BonanzaBentoGrid />

            {/* Section 7: Bold Manifesto Strip & Multi-Column Footer */}
            <BonanzaManifestoFooter />
          </main>
        )}
      </div>
    </div>
  );
};

export default App;
