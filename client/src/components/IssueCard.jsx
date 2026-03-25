import React, { useState } from 'react';
import { ChevronDown, ChevronUp, MapPin, Code2, Lightbulb, Cpu } from 'lucide-react';

const SEV_MAP = {
  Critical: { cls: 'badge-critical', dot: 'bg-red-700',   glow: 'glow-critical', border: 'border-red-600/40', ring: 'hover:border-red-600/60' },
  High:   { cls: 'badge-high',   dot: 'bg-red-500',    glow: 'glow-high',   border: 'border-red-500/30',   ring: 'hover:border-red-500/50' },
  Medium: { cls: 'badge-medium', dot: 'bg-orange-500', glow: 'glow-medium', border: 'border-orange-500/30', ring: 'hover:border-orange-500/50' },
  Low:    { cls: 'badge-low',    dot: 'bg-yellow-400',  glow: 'glow-low',    border: 'border-yellow-500/30',  ring: 'hover:border-yellow-500/50' },
};

export default function IssueCard({ issue, index, onLineClick }) {
  const [open, setOpen] = useState(index === 0);
  const sev = SEV_MAP[issue.severity] || SEV_MAP.Low;

  return (
    <div
      className={`issue-card rounded-xl border bg-shield-card ${sev.border} ${sev.ring} transition-all duration-200`}
      style={{ animationDelay: `${index * 60}ms`, animation: 'slideUp 0.35s ease forwards', opacity: 0 }}
    >
      {/* Header — always visible */}
      <button
        className="w-full flex items-start gap-3 p-4 text-left cursor-pointer"
        onClick={() => setOpen((o) => !o)}
      >
        {/* Severity dot */}
        <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${sev.dot}`} />

        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider ${sev.cls}`}>
              {issue.severity}
            </span>
            <span className="text-[10px] text-[#475569] font-mono">{issue.id}</span>
            {issue.confidence && (
              <span className="text-[10px] font-mono text-[#64748b]">
                {issue.confidence} Confidence
              </span>
            )}
            {issue.source === 'taint' && (
              <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-900/30 text-blue-400 border border-blue-500/20">
                <Cpu size={9} /> Taint Analysis
              </span>
            )}
            {issue.source === 'ai' && (
              <span className="flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-900/30 text-purple-400 border border-purple-500/20">
                <Cpu size={9} /> AI
              </span>
            )}
          </div>
          <p className="text-sm font-semibold text-white leading-snug">
            {issue.line > 0 && (
              <button
                onClick={(e) => { e.stopPropagation(); onLineClick?.(issue.line); }}
                className="text-[#00d4ff] hover:underline mr-1 font-mono tracking-tight"
                title="Click to jump to line"
              >
                Line {issue.line}:
              </button>
            )}
            {issue.type}
          </p>
        </div>

        <span className="text-[#475569] flex-shrink-0">
          {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </span>
      </button>

      {/* Expanded body */}
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-shield-border pt-3">
          {/* Snippet */}
          {issue.snippet && (
            <Section icon={<Code2 size={12} />} label="Vulnerable Code">
              <pre className="mt-1.5 p-3 rounded-lg bg-shield-surface border border-shield-border text-xs font-mono text-red-300 overflow-x-auto leading-relaxed whitespace-pre-wrap break-all">
                {issue.snippet}
              </pre>
            </Section>
          )}

          {/* Explanation */}
          {issue.explanation && (
            <Section icon={<MapPin size={12} />} label="Why It's Vulnerable">
              <p className="text-sm text-[#94a3b8] leading-relaxed mt-1">{issue.explanation}</p>
            </Section>
          )}

          {/* Fix */}
          {issue.fix && (
            <Section icon={<Lightbulb size={12} />} label="Recommended Fix">
              <div className="mt-1.5 p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/20">
                <p className="text-xs text-emerald-300 font-mono leading-relaxed whitespace-pre-wrap">{issue.fix}</p>
              </div>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ icon, label, children }) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[#64748b]">
        {icon}
        <span className="text-[10px] font-mono uppercase tracking-wider">{label}</span>
      </div>
      {children}
    </div>
  );
}
