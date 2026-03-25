import React from 'react';
import { LANGUAGES } from '../utils/samples';

export default function LanguageSelector({ selected, onChange }) {
  return (
    <div className="flex items-center gap-1 p-1 rounded-lg bg-shield-surface border border-shield-border">
      {LANGUAGES.map((lang) => (
        <button
          key={lang.value}
          onClick={() => onChange(lang.value)}
          className={`
            flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 cursor-pointer
            ${selected === lang.value
              ? 'bg-gradient-to-r from-[#0066ff] to-[#00d4ff] text-white shadow-lg'
              : 'text-[#64748b] hover:text-white hover:bg-white/5'
            }
          `}
        >
          <span className={`font-mono text-xs font-bold ${selected === lang.value ? 'text-white/80' : 'text-[#00d4ff]'}`}>
            {lang.icon}
          </span>
          {lang.label}
        </button>
      ))}
    </div>
  );
}
