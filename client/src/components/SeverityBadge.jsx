import React from 'react';

const SEVERITY_STYLES = {
  Critical: 'bg-red-500/10 text-red-500 border-red-500/20',
  High: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
  Medium: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  Low: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
};

export default function SeverityBadge({ severity }) {
  const style = SEVERITY_STYLES[severity] || SEVERITY_STYLES.Low;
  
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider border ${style}`}>
      {severity}
    </span>
  );
}
