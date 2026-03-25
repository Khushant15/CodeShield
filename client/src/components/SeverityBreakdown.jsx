import React from 'react';

export default function SeverityBreakdown({ issues }) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  issues.forEach((i) => { if (counts[i.severity] !== undefined) counts[i.severity]++; });
  const total = issues.length || 1;

  const bars = [
    { label: 'Critical', count: counts.Critical, color: '#dc2626', bg: 'rgba(220,38,38,0.15)', track: 'rgba(220,38,38,0.08)' },
    { label: 'High',   count: counts.High,   color: '#f87171', bg: 'rgba(248,113,113,0.15)', track: 'rgba(248,113,113,0.08)' },
    { label: 'Medium', count: counts.Medium, color: '#fbbf24', bg: 'rgba(251,191,36,0.15)',  track: 'rgba(251,191,36,0.08)' },
    { label: 'Low',    count: counts.Low,    color: '#4ade80', bg: 'rgba(74,222,128,0.15)',  track: 'rgba(74,222,128,0.08)' },
  ];

  return (
    <div className="p-5 rounded-xl border border-shield-border bg-shield-card space-y-3">
      <h3 className="text-xs font-mono text-[#64748b] uppercase tracking-wider">Severity Breakdown</h3>
      {bars.map(({ label, count, color, bg, track }) => (
        <div key={label} className="space-y-1">
          <div className="flex justify-between text-xs">
            <span style={{ color }} className="font-medium">{label}</span>
            <span className="font-mono text-[#94a3b8]">{count}</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: track }}>
            <div
              className="h-full rounded-full transition-all duration-700 ease-out"
              style={{ width: `${(count / total) * 100}%`, background: color, boxShadow: `0 0 8px ${color}60` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
