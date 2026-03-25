import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';

function getScoreConfig(score) {
  if (score >= 80) return { label: 'Secure',        color: '#4ade80', bg: 'rgba(74,222,128,0.1)',  stroke: '#4ade80', Icon: ShieldCheck };
  if (score >= 60) return { label: 'Moderate Risk', color: '#fbbf24', bg: 'rgba(251,191,36,0.1)',  stroke: '#fbbf24', Icon: ShieldAlert };
  if (score >= 40) return { label: 'High Risk',     color: '#f97316', bg: 'rgba(249,115,22,0.1)',  stroke: '#f97316', Icon: ShieldAlert };
  return           { label: 'Critical',             color: '#f87171', bg: 'rgba(248,113,113,0.1)', stroke: '#f87171', Icon: ShieldX };
}

export default function ScoreGauge({ score, issueCount, analysisTime }) {
  const { label, color, bg, stroke, Icon } = getScoreConfig(score);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-4 p-6 rounded-xl border border-shield-border bg-shield-card">
      {/* SVG Ring */}
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
          {/* Track */}
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#1e2d45" strokeWidth="10" />
          {/* Progress */}
          <circle
            cx="64" cy="64" r={radius}
            fill="none"
            stroke={stroke}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 1s ease', filter: `drop-shadow(0 0 8px ${color}60)` }}
          />
        </svg>
        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-display font-bold text-3xl" style={{ color }}>{score}</span>
          <span className="text-[10px] text-[#64748b] font-mono uppercase tracking-widest">/100</span>
        </div>
      </div>

      {/* Grade badge */}
      <div className="flex items-center gap-2 px-4 py-2 rounded-full text-sm font-semibold" style={{ background: bg, color }}>
        <Icon size={15} />
        {label}
      </div>

      {/* Stats row */}
      <div className="w-full grid grid-cols-2 gap-3 mt-1">
        <StatCell label="Issues Found" value={issueCount} color={issueCount === 0 ? '#4ade80' : '#f87171'} />
        <StatCell label="Scan Time" value={`${analysisTime}ms`} color="#00d4ff" />
      </div>
    </div>
  );
}

function StatCell({ label, value, color }) {
  return (
    <div className="flex flex-col items-center p-3 rounded-lg bg-shield-surface border border-shield-border">
      <span className="text-lg font-bold font-mono" style={{ color }}>{value}</span>
      <span className="text-[10px] text-[#64748b] mt-0.5 text-center">{label}</span>
    </div>
  );
}
