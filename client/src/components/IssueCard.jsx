import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ChevronDown, 
  ChevronUp, 
  Code2, 
  Lightbulb, 
  Cpu, 
  Database, 
  Globe, 
  Lock, 
  AlertTriangle,
  FileCode
} from 'lucide-react';
import SeverityBadge from './SeverityBadge';

const TYPE_ICONS = {
  'SQL Injection': <Database size={14} className="text-blue-400" />,
  'XSS': <Globe size={14} className="text-purple-400" />,
  'Hardcoded Secret': <Lock size={14} className="text-yellow-400" />,
  'Unsafe Pattern': <AlertTriangle size={14} className="text-red-400" />,
};

const SEV_COLORS = {
  Critical: 'border-red-500/30 hover:border-red-500/50',
  High: 'border-orange-500/30 hover:border-orange-500/50',
  Medium: 'border-yellow-500/30 hover:border-yellow-500/50',
  Low: 'border-emerald-500/30 hover:border-emerald-500/50',
};

export default function IssueCard({ issue, index, onLineClick }) {
  const [isOpen, setIsOpen] = useState(index === 0);
  
  const icon = TYPE_ICONS[issue.type] || <AlertTriangle size={14} className="text-red-400" />;
  const cardBorder = SEV_COLORS[issue.severity] || SEV_COLORS.Low;

  return (
    <div 
      className={`rounded-xl border bg-shield-card/50 backdrop-blur-sm ${cardBorder} transition-all duration-300 overflow-hidden shadow-lg`}
    >
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-white/5 transition-colors group"
      >
        <div className="flex items-center gap-4 min-w-0">
          <div className="p-2 rounded-lg bg-shield-surface border border-shield-border group-hover:border-[#00d4ff]/30 transition-colors">
            {icon}
          </div>
          <div className="flex flex-col gap-1 min-w-0">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={issue.severity} />
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">{issue.id}</span>
            </div>
            <h3 className="text-sm font-semibold text-white truncate">
              {issue.type}
            </h3>
            <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono">
              <FileCode size={10} />
              <span className="truncate">{issue.file || 'unknown_file'}</span>
              <span className="px-1 py-0.5 rounded bg-slate-800 text-slate-300">L:{issue.line}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="h-8 w-px bg-shield-border" />
          <div className={`p-1.5 rounded-full bg-shield-surface text-slate-500 transition-transform duration-300 ${isOpen ? 'rotate-180 text-[#00d4ff]' : ''}`}>
            <ChevronDown size={16} />
          </div>
        </div>
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: 'easeInOut' }}
          >
            <div className="px-5 pb-5 pt-2 space-y-4 border-t border-shield-border/50 bg-shield-surface/30">
              {/* Description */}
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5 text-slate-400">
                  <span className="text-[10px] font-bold uppercase tracking-widest">Why it matters</span>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">
                  {issue.explanation || issue.description}
                </p>
              </div>

              {/* Snippet */}
              {issue.snippet && (
                <div className="space-y-1.5">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <Code2 size={12} className="text-[#00d4ff]" />
                    <span className="text-[10px] font-bold uppercase tracking-widest">Target Code</span>
                  </div>
                  <div className="relative group">
                    <pre className="p-4 rounded-lg bg-[#0a0a0f] border border-red-500/20 text-xs font-mono text-pink-300/90 overflow-x-auto leading-relaxed border-l-2 border-l-red-500 shadow-inner">
                      {issue.snippet}
                    </pre>
                    <button 
                      onClick={(e) => { e.stopPropagation(); onLineClick?.(issue.line); }}
                      className="absolute top-2 right-2 p-1.5 rounded bg-shield-surface border border-shield-border text-[#00d4ff] opacity-0 group-hover:opacity-100 transition-all hover:bg-[#00d4ff] hover:text-black shadow-lg"
                      title="Jump to line"
                    >
                      <MapPinIcon size={12} />
                    </button>
                  </div>
                </div>
              )}

              {/* Fix */}
              {issue.fix && (
                <div className="space-y-1.5">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <Lightbulb size={12} className="text-emerald-400" />
                    <span className="text-[10px] font-bold uppercase tracking-widest">Suggested Fix</span>
                  </div>
                  <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/20 text-xs text-emerald-300 font-mono leading-relaxed border-l-2 border-l-emerald-500 shadow-inner">
                    {issue.fix}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function MapPinIcon({ size }) {
  return (
    <svg 
      xmlns="http://www.w3.org/2000/svg" 
      width={size} 
      height={size} 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2" 
      strokeLinecap="round" 
      strokeLinejoin="round"
    >
      <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z" />
      <circle cx="12" cy="10" r="3" />
    </svg>
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
