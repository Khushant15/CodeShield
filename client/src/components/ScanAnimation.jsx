import React from 'react';
import { Shield } from 'lucide-react';

const STEPS = [
  'Parsing source code…',
  'Running SQL injection checks…',
  'Scanning for XSS vectors…',
  'Detecting hardcoded secrets…',
  'Checking unsafe patterns…',
  'Running AI deep analysis…',
  'Calculating security score…',
];

export default function ScanAnimation() {
  const [step, setStep] = React.useState(0);

  React.useEffect(() => {
    const id = setInterval(() => setStep((s) => (s + 1) % STEPS.length), 900);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="flex flex-col items-center justify-center h-full gap-8 py-16">
      {/* Pulsing shield */}
      <div className="relative flex items-center justify-center">
        {/* Outer ring animations */}
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="absolute rounded-full border border-[#00d4ff]/20"
            style={{
              width: `${80 + i * 36}px`,
              height: `${80 + i * 36}px`,
              animation: `ping ${1.2 + i * 0.4}s cubic-bezier(0,0,0.2,1) infinite`,
              animationDelay: `${i * 0.3}s`,
            }}
          />
        ))}
        <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-[#0066ff]/30 to-[#00d4ff]/30 border border-[#00d4ff]/30 flex items-center justify-center backdrop-blur-sm">
          <Shield size={36} className="text-[#00d4ff]" style={{ filter: 'drop-shadow(0 0 12px #00d4ff)' }} />
        </div>
      </div>

      {/* Status text */}
      <div className="text-center space-y-2">
        <h3 className="font-display font-semibold text-white text-lg">Scanning Code…</h3>
        <div className="h-5 overflow-hidden">
          <p key={step} className="text-sm text-[#64748b] font-mono" style={{ animation: 'fadeIn 0.3s ease' }}>
            {STEPS[step]}
          </p>
        </div>
      </div>

      {/* Progress bar */}
      <div className="w-56 h-1 rounded-full bg-shield-border overflow-hidden">
        <div
          className="h-full rounded-full bg-gradient-to-r from-[#0066ff] to-[#00d4ff]"
          style={{
            width: `${((step + 1) / STEPS.length) * 100}%`,
            transition: 'width 0.8s ease',
            boxShadow: '0 0 12px #00d4ff80',
          }}
        />
      </div>

      {/* Shimmer dots */}
      <div className="flex gap-2">
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="w-1.5 h-1.5 rounded-full bg-[#00d4ff]"
            style={{ animation: `pulse 1.4s ease-in-out infinite`, animationDelay: `${i * 0.15}s`, opacity: 0.4 }}
          />
        ))}
      </div>
    </div>
  );
}
