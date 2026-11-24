import React, { useState, useEffect } from 'react';
import { BonanzaNavbar } from './components/BonanzaNavbar';
import { BonanzaHero } from './components/BonanzaHero';
import { BonanzaPipelineShowcase } from './components/BonanzaPipelineShowcase';
import { BonanzaMarquee } from './components/BonanzaMarquee';
import { BonanzaCoreCards } from './components/BonanzaCoreCards';
import { BonanzaBentoGrid } from './components/BonanzaBentoGrid';
import { BonanzaManifestoFooter } from './components/BonanzaManifestoFooter';
import { EmbeddedSocWorkbench } from './components/EmbeddedSocWorkbench';
import type { TriageResult, IncidentStatus } from './types/soc';

export const App: React.FC = () => {
  const [fullScreenWorkbench, setFullScreenWorkbench] = useState(false);
  const [triageData, setTriageData] = useState<TriageResult | null>(null);
  const [loadingTriage, setLoadingTriage] = useState(false);
  const [engineOnline, setEngineOnline] = useState(true);

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
      // Backend may be starting
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
    const el = document.getElementById('pipeline-showcase');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleLaunchTriageCTA = () => {
    setFullScreenWorkbench(true);
    runInitialTriage();
  };

  return (
    <div className="min-h-screen bg-[#07090E] text-[#F3F4F6] selection:bg-cyan-500 selection:text-slate-950 flex flex-col font-sans">
      {/* Sticky Minimal Navbar */}
      <BonanzaNavbar
        fullScreenWorkbench={fullScreenWorkbench}
        onToggleFullScreen={() => setFullScreenWorkbench(!fullScreenWorkbench)}
        onLaunchTriageClick={handleLaunchTriageCTA}
        engineOnline={engineOnline}
      />

      {/* Main Content: Two-Mode Experience */}
      {fullScreenWorkbench ? (
        /* Full-Screen Distraction-Free Workbench Mode */
        <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 animate-in fade-in duration-300">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold font-grotesk text-white">Full-Screen Threat Operations Center</h2>
              <p className="text-xs text-slate-400 font-sans">Autonomous Blue-Team correlation, live syslog, and MITRE mapping</p>
            </div>
            <button
              onClick={() => setFullScreenWorkbench(false)}
              className="px-4 py-2 rounded-full text-xs font-semibold bg-white/10 hover:bg-white/20 text-slate-200 transition-colors"
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
            onToggleFullScreen={() => setFullScreenWorkbench(false)}
          />
        </main>
      ) : (
        /* Bonanza-Style Showcase Mode */
        <main className="flex-1 flex flex-col">
          {/* Section 2: Editorial Hero */}
          <BonanzaHero
            onScrollToWorkbench={scrollToWorkbench}
            onRunQuickDemo={runInitialTriage}
            loading={loadingTriage}
          />

          {/* Section 3: Interactive 4-Step Pipeline + Embedded Live Product Frame */}
          <BonanzaPipelineShowcase
            triageData={triageData}
            loading={loadingTriage}
            onRunTriage={handleRunTriage}
            onUpdateStatus={handleUpdateStatus}
            onToggleFullScreen={() => setFullScreenWorkbench(true)}
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
  );
};

export default App;
