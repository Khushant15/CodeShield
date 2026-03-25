import React from 'react';
import { Scan, Trash2, BookOpen, ChevronDown } from 'lucide-react';
import { SAMPLES } from '../utils/samples';

export default function Toolbar({ language, onAnalyze, onClear, onLoadSample, isScanning, hasCode }) {
  const [sampleOpen, setSampleOpen] = React.useState(false);
  const ref = React.useRef(null);

  React.useEffect(() => {
    function handler(e) { if (ref.current && !ref.current.contains(e.target)) setSampleOpen(false); }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {/* Analyze button */}
      <button
        onClick={onAnalyze}
        disabled={isScanning || !hasCode}
        className={`
          flex items-center gap-2 px-5 py-2.5 rounded-lg font-semibold text-sm transition-all duration-200 cursor-pointer
          ${isScanning || !hasCode
            ? 'bg-shield-border text-[#475569] cursor-not-allowed'
            : 'bg-gradient-to-r from-[#0066ff] to-[#00d4ff] text-white hover:shadow-lg hover:shadow-[#0066ff]/30 hover:scale-105 active:scale-95'
          }
        `}
      >
        <Scan size={15} className={isScanning ? 'animate-spin' : ''} />
        {isScanning ? 'Scanning…' : 'Analyze Code'}
      </button>

      {/* Load sample dropdown */}
      <div className="relative" ref={ref}>
        <button
          onClick={() => setSampleOpen((o) => !o)}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg border border-shield-border text-sm text-[#94a3b8] hover:text-white hover:border-[#00d4ff]/40 transition-all cursor-pointer"
        >
          <BookOpen size={14} />
          Load Sample
          <ChevronDown size={12} className={`transition-transform ${sampleOpen ? 'rotate-180' : ''}`} />
        </button>

        {sampleOpen && (
          <div className="absolute top-full left-0 mt-1 w-44 rounded-xl border border-shield-border bg-shield-card shadow-xl z-50 overflow-hidden"
               style={{ animation: 'fadeIn 0.15s ease' }}>
            {['vulnerable', 'safe'].map((type) => (
              <button
                key={type}
                onClick={() => { onLoadSample(type); setSampleOpen(false); }}
                className="w-full flex items-center gap-2.5 px-4 py-3 text-sm hover:bg-shield-surface transition-colors text-left cursor-pointer"
              >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${type === 'vulnerable' ? 'bg-red-400' : 'bg-emerald-400'}`} />
                <span className={type === 'vulnerable' ? 'text-red-300' : 'text-emerald-300'}>
                  {type === 'vulnerable' ? 'Vulnerable Code' : 'Secure Code'}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Clear button */}
      <button
        onClick={onClear}
        disabled={!hasCode}
        className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg border border-shield-border text-sm text-[#64748b] hover:text-red-400 hover:border-red-500/30 transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
      >
        <Trash2 size={14} />
        Clear
      </button>
    </div>
  );
}
