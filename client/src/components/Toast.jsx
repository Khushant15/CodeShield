import React, { useEffect } from 'react';
import { CheckCircle, XCircle, AlertCircle, X } from 'lucide-react';

const ICONS = {
  success: <CheckCircle size={16} className="text-emerald-400" />,
  error:   <XCircle size={16} className="text-red-400" />,
  info:    <AlertCircle size={16} className="text-[#00d4ff]" />,
};

const COLORS = {
  success: 'border-emerald-500/30 bg-emerald-950/60',
  error:   'border-red-500/30 bg-red-950/60',
  info:    'border-[#00d4ff]/30 bg-[#0066ff]/10',
};

export default function Toast({ message, type = 'info', onClose }) {
  useEffect(() => {
    const t = setTimeout(onClose, 4500);
    return () => clearTimeout(t);
  }, []);

  return (
    <div
      className={`flex items-start gap-3 px-4 py-3 rounded-xl border backdrop-blur-md shadow-xl max-w-sm ${COLORS[type]}`}
      style={{ animation: 'slideUp 0.25s ease' }}
    >
      <span className="mt-0.5 flex-shrink-0">{ICONS[type]}</span>
      <p className="text-sm text-white flex-1 leading-snug">{message}</p>
      <button onClick={onClose} className="flex-shrink-0 text-[#64748b] hover:text-white transition-colors cursor-pointer">
        <X size={14} />
      </button>
    </div>
  );
}

export function ToastContainer({ toasts, onRemove }) {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <Toast key={t.id} message={t.message} type={t.type} onClose={() => onRemove(t.id)} />
      ))}
    </div>
  );
}
