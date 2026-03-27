import React, { useState, useEffect } from 'react';
import { Shield, Github, Zap, Brain, AlertCircle } from 'lucide-react';
import { checkHealth } from '../services/api';

export default function Header({ isConnected }) {
  const [aiStatus, setAiStatus] = useState(null); // null | 'ok' | 'disabled' | 'error'
  const [aiProvider, setAiProvider] = useState('');

  useEffect(() => {
    checkHealth()
      .then((data) => {
        setAiProvider(data.aiProvider || 'none');
        if (data.aiProvider === 'none') {
          setAiStatus('disabled');
        } else if (data.aiKeySet) {
          setAiStatus('ok');
        } else {
          setAiStatus('error');
        }
      })
      .catch(() => setAiStatus('error'));
  }, []);

  const aiLabel =
    aiStatus === 'ok' ? `AI (${aiProvider})` :
      aiStatus === 'disabled' ? 'Static only' :
        aiStatus === 'error' ? 'AI key missing' : '';

  const aiBadgeClass =
    aiStatus === 'ok' ? 'text-purple-400 bg-purple-900/20 border-purple-500/20' :
      aiStatus === 'disabled' ? 'text-[#64748b] bg-shield-card border-shield-border' :
        aiStatus === 'error' ? 'text-yellow-400 bg-yellow-900/20 border-yellow-500/20' : '';

  return (
    <header className="relative z-10 border-b border-shield-border bg-shield-surface/90 backdrop-blur-md">
      <div className="max-w-screen-xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
        {/* Logo */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <div className="relative">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#00d4ff] to-[#0066ff] flex items-center justify-center shadow-lg shadow-[#0066ff]/30">
              <Shield size={18} className="text-white" />
            </div>
            <span className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full border-2 border-shield-surface ${isConnected ? 'bg-emerald-400' : 'bg-red-500'}`} />
          </div>
          <div>
            <h1 className="font-display font-bold text-lg text-white leading-none">
              Code<span className="text-[#00d4ff]">Shield</span>
            </h1>
            <p className="text-[10px] text-[#64748b] font-mono tracking-wider uppercase mt-0.5">Security Analyzer</p>
          </div>
        </div>

        {/* Centre pills */}
        <div className="hidden md:flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-shield-border bg-shield-card text-xs font-mono text-[#64748b]">
            <Zap size={10} className="text-[#00d4ff]" />
            Static Analysis
          </div>
          {aiStatus && (
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-mono ${aiBadgeClass}`}>
              {aiStatus === 'error' ? <AlertCircle size={10} /> : <Brain size={10} />}
              {aiLabel}
            </div>
          )}
        </div>

        {/* Right: status + github */}
        <div className="flex items-center gap-3 flex-shrink-0">
          {/* AI warning tooltip */}
          {aiStatus === 'error' && (
            <div className="hidden sm:flex items-center gap-1.5 text-xs text-yellow-400 bg-yellow-900/20 border border-yellow-500/20 px-2.5 py-1 rounded-lg">
              <AlertCircle size={11} />
              Set AI key in server/.env
            </div>
          )}
          <div className="flex items-center gap-1.5 text-xs">
            <span className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`} />
            <span className={isConnected ? 'text-emerald-400' : 'text-red-400'}>
              {isConnected ? 'API Online' : 'API Offline'}
            </span>
          </div>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 rounded-lg border border-shield-border text-[#64748b] hover:text-white hover:border-[#00d4ff]/40 transition-all"
          >
            <Github size={15} />
          </a>
        </div>
      </div>
    </header>
  );
}
