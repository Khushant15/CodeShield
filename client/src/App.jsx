import React, { useState, useEffect, useCallback, useRef } from 'react';
import Header         from './components/Header';
import CodeEditor     from './components/CodeEditor';
import ResultsPanel   from './components/ResultsPanel';
import ScanAnimation  from './components/ScanAnimation';
import Toolbar        from './components/Toolbar';
import LanguageSelector from './components/LanguageSelector';
import { ToastContainer } from './components/Toast';
import { useToast }   from './hooks/useToast';
import { analyzeCode, checkHealth } from './services/api';
import { SAMPLES }    from './utils/samples';

export default function App() {
  const [language,   setLanguage]   = useState('javascript');
  const [code,       setCode]       = useState(SAMPLES.javascript.vulnerable);
  const [result,     setResult]     = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isConnected,setConnected]  = useState(false);
  const [issueLines, setIssueLines] = useState([]);
  const { toasts, push, remove }    = useToast();

  // Health-check on mount
  useEffect(() => {
    checkHealth()
      .then(() => setConnected(true))
      .catch(() => {
        setConnected(false);
        push('Backend offline — run: cd codeshield && npm run dev:server', 'error');
      });
  }, []);

  const handleLanguageChange = useCallback((lang) => {
    setLanguage(lang);
    setCode(SAMPLES[lang]?.vulnerable || '');
    setResult(null);
    setIssueLines([]);
  }, []);

  const handleLoadSample = useCallback((type) => {
    const sample = SAMPLES[language]?.[type];
    if (sample) {
      setCode(sample);
      setResult(null);
      setIssueLines([]);
      push(
        `Loaded ${type} ${language} sample`,
        type === 'vulnerable' ? 'error' : 'success'
      );
    }
  }, [language]);

  const handleClear = useCallback(() => {
    setCode('');
    setResult(null);
    setIssueLines([]);
  }, []);

  const handleAnalyze = useCallback(async () => {
    const trimmed = code?.trim();
    if (!trimmed) { push('Please enter some code to analyze.', 'info'); return; }
    if (trimmed.length < 10) { push('Code is too short to analyze.', 'info'); return; }
    if (isScanning) return;

    setIsScanning(true);
    setResult(null);
    setIssueLines([]);

    try {
      const data = await analyzeCode({ code, language });

      setResult(data);

      // Extract unique vulnerable line numbers for editor highlighting
      const lines = [...new Set(
        (data.issues || [])
          .filter((i) => i.line > 0)
          .map((i) => i.line)
      )];
      setIssueLines(lines);

      // Toast summary
      const high = (data.issues || []).filter((i) => i.severity === 'High').length;
      if (data.issues.length === 0) {
        push('No vulnerabilities detected — code looks clean!', 'success');
      } else {
        push(
          `Found ${data.issues.length} issue${data.issues.length !== 1 ? 's' : ''} · Score: ${data.score}/100${high > 0 ? ` · ${high} critical` : ''}`,
          high > 0 ? 'error' : 'info'
        );
      }
    } catch (err) {
      push(err.message || 'Analysis failed — check browser console for details.', 'error');
      console.error('[CodeShield] Analysis error:', err);
    } finally {
      setIsScanning(false);
    }
  }, [code, language, isScanning]);

  // Jump to line when user clicks line number in a result card
  const handleLineClick = useCallback((line) => {
    window.dispatchEvent(new CustomEvent('codeshield:jumpToLine', { detail: { line } }));
  }, []);

  return (
    <div className="min-h-screen bg-shield-bg grid-bg flex flex-col">
      <Header isConnected={isConnected} />

      <main className="flex-1 flex flex-col max-w-screen-2xl w-full mx-auto px-4 md:px-6 py-4 gap-4 overflow-hidden">

        {/* Top bar */}
        <div className="flex flex-wrap items-center gap-3 justify-between">
          <LanguageSelector selected={language} onChange={handleLanguageChange} />
          <Toolbar
            language={language}
            onAnalyze={handleAnalyze}
            onClear={handleClear}
            onLoadSample={handleLoadSample}
            isScanning={isScanning}
            hasCode={!!(code?.trim())}
          />
        </div>

        {/* Editor + Results */}
        <div
          className="flex-1 grid grid-cols-1 lg:grid-cols-[1fr_380px] xl:grid-cols-[1fr_430px] gap-4 min-h-0"
          style={{ height: 'calc(100vh - 148px)' }}
        >
          {/* Monaco Editor */}
          <div className="flex flex-col min-h-0">
            <CodeEditor
              code={code}
              onChange={setCode}
              language={language}
              issues={result?.issues || []}
            />
          </div>

          {/* Results / Scan Panel */}
          <div className="relative flex flex-col border border-shield-border rounded-xl bg-shield-surface overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-shield-border bg-shield-card/60 flex-shrink-0">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[#00d4ff] animate-pulse" />
                <span className="text-xs font-mono text-[#64748b] uppercase tracking-wider">
                  {isScanning ? 'Scanning…' : result ? 'Analysis Results' : 'Security Report'}
                </span>
              </div>
              {result && (
                <span className="text-[10px] font-mono text-[#334155]">
                  {result.issues.length} issue{result.issues.length !== 1 ? 's' : ''} · {result.language}
                </span>
              )}
            </div>

            <div className="flex-1 overflow-y-auto px-4 py-4">
              {isScanning
                ? <ScanAnimation />
                : <ResultsPanel result={result} onLineClick={handleLineClick} />
              }
            </div>
          </div>
        </div>
      </main>

      <ToastContainer toasts={toasts} onRemove={remove} />

      {/* Ambient glows */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden -z-10">
        <div className="absolute top-0 left-1/4 w-96 h-96 rounded-full bg-[#0066ff]/5 blur-3xl" />
        <div className="absolute bottom-1/4 right-1/3 w-80 h-80 rounded-full bg-[#00d4ff]/4 blur-3xl" />
      </div>
    </div>
  );
}
