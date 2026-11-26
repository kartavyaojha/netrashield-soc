import React, { useState, useEffect } from 'react';
import {
  FileCode,
  Plus,
  Trash2,
  Save,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  Code2,
  Eye,
  Terminal,
  ShieldCheck,
  Tag
} from 'lucide-react';
import { sound } from '../utils/audio';

interface SigmaRule {
  id: string;
  title: string;
  level: string;
  description: string;
  tags: string[];
  raw_yaml: string;
  file_name: string;
}

const TEMPLATE_RULE = `title: Suspicious PowerShell Download Cradle
id: custom-ps-cradle-01
status: experimental
description: Detects PowerShell downloading and executing code via WebClient or IEX
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: NetraShield SOC Analyst
date: 2026/11/26
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process_command|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'Net.WebClient'
      - 'Invoke-Expression'
      - 'IEX'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
`;

export const SigmaStudioView: React.FC = () => {
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedRuleId, setSelectedRuleId] = useState<string>('');
  const [ruleFilename, setRuleFilename] = useState<string>('custom_ps_cradle.yml');
  const [yamlContent, setYamlContent] = useState<string>(TEMPLATE_RULE);
  const [saving, setSaving] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/rules');
      if (res.ok) {
        const data = await res.json();
        setRules(data.rules || []);
        if (data.rules && data.rules.length > 0 && !selectedRuleId) {
          const first = data.rules[0];
          setSelectedRuleId(first.id);
          setRuleFilename(first.file_name);
          setYamlContent(first.raw_yaml);
        }
      }
    } catch (err) {
      console.error('Failed fetching rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleSelectRule = (rule: SigmaRule) => {
    sound.playTick();
    setSelectedRuleId(rule.id);
    setRuleFilename(rule.file_name);
    setYamlContent(rule.raw_yaml);
    setStatusMessage(null);
  };

  const handleNewRule = () => {
    sound.playChirp();
    const newId = `custom_rule_${Date.now().toString().slice(-4)}`;
    setSelectedRuleId(newId);
    setRuleFilename(`${newId}.yml`);
    setYamlContent(TEMPLATE_RULE.replace('custom-ps-cradle-01', newId));
    setStatusMessage(null);
  };

  const handleSaveRule = async () => {
    sound.playTick();
    setSaving(true);
    setStatusMessage(null);

    // Basic client-side check
    if (!yamlContent.includes('title:') || !yamlContent.includes('detection:')) {
      setStatusMessage({
        type: 'error',
        text: 'Validation failed: Sigma rule must contain both "title:" and "detection:" sections.'
      });
      setSaving(false);
      return;
    }

    try {
      const res = await fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rule_id: ruleFilename.replace(/\.ya?ml$/i, ''),
          yaml_content: yamlContent
        })
      });

      if (res.ok) {
        sound.playAlertPulse();
        const data = await res.json();
        setStatusMessage({
          type: 'success',
          text: `Rule saved & engine reloaded. Active rules: ${data.rules_count}`
        });
        await fetchRules();
      } else {
        const err = await res.json();
        setStatusMessage({
          type: 'error',
          text: err.detail || 'Failed to save rule'
        });
      }
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || 'Connection error'
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteRule = async (ruleId: string, filename: string) => {
    if (!window.confirm(`Delete rule "${filename}"? This action cannot be undone.`)) {
      return;
    }
    sound.playTick();
    try {
      const res = await fetch(`/api/rules/${encodeURIComponent(filename)}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        sound.playAlertPulse();
        setStatusMessage({ type: 'success', text: `Deleted rule ${filename}` });
        await fetchRules();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const filteredRules = rules.filter(r =>
    r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    r.file_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (r.tags && r.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase())))
  );

  // Live syntax inspection
  const isSyntaxValid = yamlContent.includes('title:') && yamlContent.includes('detection:');

  return (
    <div className="space-y-5 font-sans">
      {/* Top Banner / Control Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bonanza-card p-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400">
            <Code2 className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center space-x-2 font-grotesk">
              <span>Sigma Rule Studio</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-500/15 text-violet-300 border border-indigo-500/30 font-mono">
                {rules.length} Active Rules Loaded
              </span>
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Draft, compile, test, and hot-reload open Sigma detection rules directly into the engine.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={fetchRules}
            disabled={loading}
            className="px-3 py-2 rounded-xl text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-white/10 flex items-center space-x-1.5 transition-all"
            title="Reload from disk"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Reload</span>
          </button>
          <button
            onClick={handleNewRule}
            className="px-3 py-2 rounded-xl text-xs font-semibold bg-white/5 hover:bg-white/10 text-white border border-white/10 flex items-center space-x-1.5 transition-all"
          >
            <Plus className="w-3.5 h-3.5 text-emerald-400" />
            <span>New Rule</span>
          </button>
        </div>
      </div>

      {/* Main Split Pane Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Rule Selector & Filter */}
        <div className="lg:col-span-4 bonanza-card p-4 flex flex-col space-y-3 max-h-[640px]">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search Sigma rules, tags..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-[#141221] border border-white/10 rounded-xl pl-8 pr-3 py-1.5 text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-indigo-400 font-mono"
            />
          </div>

          <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
            {filteredRules.length === 0 ? (
              <div className="py-8 text-center text-xs text-zinc-500 font-mono">
                No Sigma rules found matching filter.
              </div>
            ) : (
              filteredRules.map(rule => {
                const isSelected = selectedRuleId === rule.id;
                return (
                  <div
                    key={rule.id}
                    onClick={() => handleSelectRule(rule)}
                    className={`p-3 rounded-xl border text-left cursor-pointer transition-all flex items-start justify-between group ${
                      isSelected
                        ? 'bg-indigo-600/20 border-indigo-400/50 shadow-[0_0_15px_rgba(99,102,241,0.2)]'
                        : 'bg-[#13121F] border-white/5 hover:border-white/15'
                    }`}
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.2 rounded border ${
                            rule.level === 'critical'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                              : rule.level === 'high'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-indigo-500/10 text-violet-300 border-indigo-500/20'
                          }`}
                        >
                          {rule.level || 'RULE'}
                        </span>
                        <h4 className="text-xs font-semibold text-white truncate">{rule.title}</h4>
                      </div>
                      <div className="text-[11px] font-mono text-zinc-400 mt-1 truncate">
                        {rule.file_name}
                      </div>
                      {rule.tags && rule.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1.5">
                          {rule.tags.slice(0, 2).map(tag => (
                            <span key={tag} className="text-[9px] font-mono px-1 rounded bg-white/5 text-zinc-400">
                              {tag.replace('attack.', '')}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    <button
                      onClick={e => {
                        e.stopPropagation();
                        handleDeleteRule(rule.id, rule.file_name);
                      }}
                      className="opacity-0 group-hover:opacity-100 p-1 text-zinc-500 hover:text-rose-400 transition-opacity"
                      title="Delete rule"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Code Editor & Action Bar */}
        <div className="lg:col-span-8 bonanza-card p-5 flex flex-col space-y-4">
          {/* Header Row */}
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-white/10">
            <div className="flex items-center space-x-2 flex-1 min-w-[200px]">
              <FileCode className="w-4 h-4 text-violet-400" />
              <input
                type="text"
                value={ruleFilename}
                onChange={e => setRuleFilename(e.target.value)}
                placeholder="rule_filename.yml"
                className="bg-[#141221] border border-white/10 rounded-lg px-2.5 py-1 text-xs text-white font-mono focus:outline-none focus:border-indigo-400 flex-1"
              />
            </div>

            <div className="flex items-center space-x-3">
              {/* Syntax Validation Indicator */}
              <div
                className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border ${
                  isSyntaxValid
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                }`}
              >
                {isSyntaxValid ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Valid Sigma Syntax</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Missing Title/Detection</span>
                  </>
                )}
              </div>

              {/* Save & Hot-Reload Button */}
              <button
                onClick={handleSaveRule}
                disabled={saving}
                className="px-4 py-1.5 rounded-xl text-xs font-bold text-white bg-[#FF4D2D] hover:bg-[#ff3b18] shadow-sm flex items-center space-x-1.5 transition-all disabled:opacity-50"
              >
                {saving ? (
                  <span className="inline-block animate-spin rounded-full h-3.5 w-3.5 border-2 border-white border-t-transparent" />
                ) : (
                  <>
                    <Save className="w-3.5 h-3.5" />
                    <span>Save & Compile</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Status Alert if any */}
          {statusMessage && (
            <div
              className={`p-3 rounded-xl text-xs font-mono flex items-center space-x-2 ${
                statusMessage.type === 'success'
                  ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-500/10 border border-rose-500/30 text-rose-300'
              }`}
            >
              {statusMessage.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span>{statusMessage.text}</span>
            </div>
          )}

          {/* Monospace YAML Editor Area */}
          <div className="relative flex-1">
            <textarea
              value={yamlContent}
              onChange={e => setYamlContent(e.target.value)}
              spellCheck={false}
              rows={22}
              className="w-full bg-[#0A0912] border border-white/10 rounded-xl p-4 font-mono text-xs text-violet-200 leading-relaxed focus:outline-none focus:border-indigo-400 focus:ring-1 focus:ring-indigo-400 resize-none selection:bg-indigo-600/30"
              placeholder="Paste or write Sigma YAML detection rule here..."
            />
          </div>

          <div className="flex items-center justify-between text-[11px] font-mono text-zinc-500 pt-1">
            <span>Detection Backend: Regex & Substring Keyword Matching</span>
            <span>Target: ECS Normalized Telemetry</span>
          </div>
        </div>
      </div>
    </div>
  );
};
