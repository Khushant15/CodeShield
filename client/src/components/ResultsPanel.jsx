import React, { useState, useMemo } from 'react';
import { ShieldCheck, Filter, AlertTriangle } from 'lucide-react';
import IssueCard from './IssueCard';
import ScoreGauge from './ScoreGauge';
import SeverityBreakdown from './SeverityBreakdown';

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

export default function ResultsPanel({ result, onLineClick }) {
  const [filter, setFilter] = useState('All');

  const filtered = useMemo(() => {
    const issues = result?.issues || [];
    return filter === 'All' ? issues : issues.filter((i) => i.severity === filter);
  }, [result, filter]);

  const counts = useMemo(() => {
    const issues = result?.issues || [];
    return {
      All:      issues.length,
      Critical: issues.filter((i) => i.severity === 'Critical').length,
      High:     issues.filter((i) => i.severity === 'High').length,
      Medium:   issues.filter((i) => i.severity === 'Medium').length,
      Low:      issues.filter((i) => i.severity === 'Low').length,
    };
  }, [result]);

  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center gap-4 py-20 text-[#334155]">
        <div className="w-16 h-16 rounded-2xl border border-shield-border bg-shield-card flex items-center justify-center">
          <ShieldCheck size={28} className="text-shield-border" />
        </div>
        <div>
          <p className="font-semibold text-[#475569]">No Analysis Yet</p>
          <p className="text-sm mt-1 text-[#334155]">Paste your code and click Analyze</p>
        </div>
      </div>
    );
  }

  const { score, issues, analysisTime } = result;

  return (
    <div className="flex flex-col gap-4 h-full overflow-y-auto pr-1">
      {/* Score + breakdown */}
      <ScoreGauge score={score} issueCount={issues.length} analysisTime={analysisTime} />
      {issues.length > 0 && <SeverityBreakdown issues={issues} />}

      {/* Filter tabs */}
      {issues.length > 0 && (
        <div className="flex items-center gap-1 p-1 rounded-lg bg-shield-surface border border-shield-border">
          {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => {
            const active = filter === sev;
            const dotColors = { Critical: 'bg-red-600', High: 'bg-red-400', Medium: 'bg-yellow-400', Low: 'bg-green-400', All: 'bg-[#00d4ff]' };
            return (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs font-medium transition-all cursor-pointer
                  ${active ? 'bg-shield-card text-white shadow' : 'text-[#64748b] hover:text-[#94a3b8]'}`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${dotColors[sev]}`} />
                {sev}
                <span className={`text-[10px] font-mono ${active ? 'text-[#64748b]' : 'text-[#334155]'}`}>
                  {counts[sev]}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {/* No issues banner */}
      {issues.length === 0 && (
        <div className="flex flex-col items-center gap-3 p-6 rounded-xl border border-emerald-500/20 bg-emerald-950/20 text-center">
          <ShieldCheck size={32} className="text-emerald-400" />
          <div>
            <p className="font-semibold text-emerald-400">No Vulnerabilities Detected</p>
            <p className="text-xs text-[#64748b] mt-1">This code looks clean based on our analysis.</p>
          </div>
        </div>
      )}

      {/* Issue cards */}
      {filtered.length === 0 && issues.length > 0 && (
        <div className="flex items-center justify-center gap-2 py-6 text-sm text-[#475569]">
          <Filter size={14} />
          No {filter} issues found
        </div>
      )}

      <div className="space-y-3 pb-4">
        {filtered.map((issue, idx) => (
          <IssueCard key={issue.id} issue={issue} index={idx} onLineClick={onLineClick} />
        ))}
      </div>

      {/* Footer */}
      {issues.length > 0 && (
        <div className="flex items-center gap-1.5 text-[11px] text-[#334155] font-mono pb-2">
          <AlertTriangle size={10} />
          {issues.length} issue{issues.length !== 1 ? 's' : ''} found · static + AI analysis
        </div>
      )}
    </div>
  );
}
