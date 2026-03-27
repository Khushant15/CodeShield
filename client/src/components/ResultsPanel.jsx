import React from 'react';
import { ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';
import IssueList from './IssueList';
import ScoreGauge from './ScoreGauge';
import SeverityBreakdown from './SeverityBreakdown';

export default function ResultsPanel({ result, onLineClick }) {
  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center gap-4 py-20 text-slate-500">
        <div className="w-16 h-16 rounded-2xl border border-shield-border bg-shield-card flex items-center justify-center shadow-xl animate-pulse">
          <ShieldCheck size={28} className="text-shield-border" />
        </div>
        <div>
          <p className="font-semibold text-slate-400">No Analysis Yet</p>
          <p className="text-xs mt-1 text-slate-500">Paste your code and click Analyze to scan for vulnerabilities.</p>
        </div>
      </div>
    );
  }

  const { score, issues, summary, analysisTime } = result;

  return (
    <div className="flex flex-col gap-6 h-full overflow-y-auto pr-2 custom-scrollbar pb-8">
      {/* Score + Global Metrics */}
      <div className="grid grid-cols-1 gap-4">
        <ScoreGauge score={score} issueCount={issues.length} analysisTime={analysisTime} />
        {issues.length > 0 && <SeverityBreakdown issues={issues} />}
      </div>

      {/* Main Content Area */}
      <div className="space-y-4">
        <div className="flex items-center justify-between px-1">
          <div className="flex flex-col">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-500">Security Audit</h3>
            <span className="text-[10px] font-mono text-slate-600">
              Found {issues.length} potential {issues.length === 1 ? 'threat' : 'threats'}
            </span>
          </div>
          {issues.length > 0 && (
            <div className="px-2 py-0.5 rounded bg-shield-surface border border-shield-border text-[9px] font-mono text-slate-500">
              {analysisTime}ms scan
            </div>
          )}
        </div>

        {/* Empty State / Success */}
        {issues.length === 0 ? (
          <div className="flex flex-col items-center gap-4 p-10 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 text-center shadow-[0_0_40px_-15px_rgba(16,185,129,0.1)]">
            <div className="p-4 rounded-full bg-emerald-500/10 border border-emerald-500/20">
              <CheckCircle2 size={32} className="text-emerald-400" />
            </div>
            <div className="max-w-[240px]">
              <p className="font-bold text-emerald-400">No Vulnerabilities Detected</p>
              <p className="text-xs text-slate-500 mt-2 leading-relaxed">
                Your code is secure. No known security patterns were identified in this scan.
              </p>
            </div>
          </div>
        ) : (
          /* Detailed Issue List with Filtering/Sorting */
          <IssueList
            issues={issues}
            onLineClick={onLineClick}
            summary={summary}
          />
        )}
      </div>

      {/* Footer Info */}
      <div className="mt-4 pt-4 border-t border-shield-border/30 flex items-center justify-between text-[10px] font-mono text-slate-600 px-1">
        <div className="flex items-center gap-1.5">
          <AlertTriangle size={10} className="text-orange-500/50" />
          Powered by Static Analysis
        </div>
        <div className="opacity-50">
          v2.0.0-final
        </div>
      </div>
    </div>
  );
}
