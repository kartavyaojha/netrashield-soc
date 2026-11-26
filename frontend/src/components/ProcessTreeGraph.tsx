import React from 'react';
import { Server, Terminal, ShieldAlert, Globe, ArrowRight, CornerDownRight } from 'lucide-react';
import type { AlertIncident } from '../types/soc';

interface ProcessTreeGraphProps {
  incident: AlertIncident;
}

export const ProcessTreeGraph: React.FC<ProcessTreeGraphProps> = ({ incident }) => {
  const host = incident.host || 'unknown-host';
  const parentName = (incident.raw_ecs?.process as any)?.parent?.name || 'services.exe';
  const parentPid = (incident.raw_ecs?.process as any)?.parent?.pid || 1024;
  const procName = incident.process_image ? incident.process_image.split(/[\\/]/).pop() : 'powershell.exe';
  const procCmd = incident.process_command || procName || 'cmd.exe';
  const destIp = incident.dest_ip;
  const destPort = incident.dest_port || 443;
  const mitreTag = incident.mitre_id ? `${incident.mitre_id} (${incident.mitre_name})` : 'T1059.001';

  return (
    <div className="rounded-xl bg-[#0E0D17] border border-white/10 p-4 space-y-3 font-sans">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400 font-semibold flex items-center gap-1.5">
          <Terminal className="w-3.5 h-3.5 text-violet-400" />
          <span>Visual Attack Storyline & Process Lineage</span>
        </span>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 text-zinc-400 border border-white/10">
          Linear Trace
        </span>
      </div>

      <div className="space-y-2 relative">
        {/* Step 1: Endpoint Host */}
        <div className="flex items-center space-x-3 p-2.5 rounded-lg bg-[#141322] border border-white/5 hover:border-white/15 transition-all">
          <div className="p-2 rounded-md bg-white/5 border border-white/10 text-zinc-300">
            <Server className="w-4 h-4 text-zinc-300" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider">Endpoint Host</span>
              <span className="text-[10px] font-mono text-emerald-400">Ingested</span>
            </div>
            <div className="text-xs font-mono font-semibold text-white truncate">{host}</div>
          </div>
        </div>

        {/* Connector */}
        <div className="flex items-center pl-6 text-zinc-600 text-xs">
          <CornerDownRight className="w-4 h-4 text-zinc-500" />
          <span className="text-[10px] font-mono text-zinc-500 ml-1.5">spawned by service manager</span>
        </div>

        {/* Step 2: Parent Process */}
        <div className="flex items-center space-x-3 p-2.5 rounded-lg bg-[#141322] border border-white/5 hover:border-white/15 transition-all">
          <div className="p-2 rounded-md bg-white/5 border border-white/10 text-zinc-300">
            <Terminal className="w-4 h-4 text-zinc-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wider">Parent Process</span>
              <span className="text-[10px] font-mono text-zinc-500">PID {parentPid}</span>
            </div>
            <div className="text-xs font-mono font-medium text-zinc-200 truncate">{parentName}</div>
          </div>
        </div>

        {/* Connector */}
        <div className="flex items-center pl-6 text-zinc-600 text-xs">
          <CornerDownRight className="w-4 h-4 text-[#FF4D2D]" />
          <span className="text-[10px] font-mono text-[#FF4D2D] ml-1.5 font-medium">suspicious child execution</span>
        </div>

        {/* Step 3: Malicious Execution & Command Line */}
        <div className="p-2.5 rounded-lg bg-[#1C141E] border border-rose-500/30 shadow-[0_0_15px_rgba(255,77,45,0.08)]">
          <div className="flex items-start space-x-3">
            <div className="p-2 rounded-md bg-rose-500/10 border border-rose-500/30 text-rose-400 mt-0.5">
              <ShieldAlert className="w-4 h-4 text-[#FF4D2D]" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono text-rose-300 uppercase tracking-wider font-semibold">
                  Detected Process Execution
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  Anomaly Score: {incident.risk_score}
                </span>
              </div>
              <div className="text-xs font-mono font-bold text-white mt-0.5">{procName}</div>
              <div className="text-[11px] font-mono text-rose-200/90 bg-black/40 p-1.5 rounded mt-1.5 break-all border border-rose-500/10 max-h-20 overflow-y-auto">
                {procCmd}
              </div>
            </div>
          </div>
        </div>

        {/* Connector */}
        <div className="flex items-center pl-6 text-zinc-600 text-xs">
          <CornerDownRight className="w-4 h-4 text-violet-400" />
          <span className="text-[10px] font-mono text-violet-400 ml-1.5">network egress & ATT&CK tag</span>
        </div>

        {/* Step 4: Destination C2 / IOC / MITRE */}
        <div className="flex items-center space-x-3 p-2.5 rounded-lg bg-[#151426] border border-indigo-500/20 hover:border-indigo-500/40 transition-all">
          <div className="p-2 rounded-md bg-indigo-500/10 border border-indigo-500/20 text-violet-300">
            <Globe className="w-4 h-4 text-violet-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-violet-300 uppercase tracking-wider">C2 Target / MITRE Technique</span>
              <span className="text-[10px] font-mono text-violet-400">{destPort ? `Port ${destPort}` : 'Egress'}</span>
            </div>
            <div className="text-xs font-mono font-semibold text-white truncate">
              {destIp ? `${destIp}:${destPort}` : 'External Network Communication'}
            </div>
            <div className="text-[10px] font-mono text-zinc-400 mt-0.5 truncate">{mitreTag}</div>
          </div>
        </div>
      </div>
    </div>
  );
};
