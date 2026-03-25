import React, { useRef, useCallback } from 'react';
import Editor, { useMonaco } from '@monaco-editor/react';
import { SAMPLES } from '../utils/samples';

const MONACO_THEME = {
  base: 'vs-dark',
  inherit: true,
  rules: [
    { token: 'comment',   foreground: '4a5568', fontStyle: 'italic' },
    { token: 'keyword',   foreground: '00d4ff' },
    { token: 'string',    foreground: '4ade80' },
    { token: 'number',    foreground: 'fbbf24' },
    { token: 'type',      foreground: 'a78bfa' },
    { token: 'function',  foreground: '38bdf8' },
    { token: 'variable',  foreground: 'e2e8f0' },
  ],
  colors: {
    'editor.background':           '#0d1421',
    'editor.foreground':           '#e2e8f0',
    'editorLineNumber.foreground': '#334155',
    'editorLineNumber.activeForeground': '#00d4ff',
    'editor.lineHighlightBackground': '#1e2d4520',
    'editorCursor.foreground':     '#00d4ff',
    'editor.selectionBackground':  '#0066ff30',
    'editorIndentGuide.background': '#1e2d45',
    'editorIndentGuide.activeBackground': '#2d4a6e',
    'scrollbarSlider.background':  '#1e2d4560',
    'scrollbarSlider.hoverBackground': '#2d4a6e80',
  },
};

export default function CodeEditor({ code, onChange, language, issues = [] }) {
  const editorRef = useRef(null);
  const monaco = useMonaco();
  const decorationsRef = useRef([]);

  const handleEditorDidMount = useCallback((editor, monacoInstance) => {
    editorRef.current = editor;
    monacoInstance.editor.defineTheme('codeshield', MONACO_THEME);
    monacoInstance.editor.setTheme('codeshield');
    applyDecorations(editor, monacoInstance, issues);
  }, [issues]);

  const applyDecorations = (editor, monacoInstance, issueList) => {
    if (!editor || !monacoInstance) return;
    
    // Clear old decorations
    const oldIds = decorationsRef.current || [];
    
    if (!issueList?.length) {
      decorationsRef.current = editor.deltaDecorations(oldIds, []);
      return;
    }

    const SEV_COLORS = {
      Critical: { bg: 'bg-red-900/30 border-l-[3px] border-red-500',   hex: '#dc2626' },
      High:     { bg: 'bg-red-900/10 border-l-2 border-red-400',       hex: '#f87171' },
      Medium:   { bg: 'bg-yellow-900/10 border-l-2 border-yellow-400', hex: '#fbbf24' },
      Low:      { bg: 'bg-green-900/10 border-l-2 border-green-400',   hex: '#4ade80' },
    };

    const newDecorations = issueList.filter(i => i.line > 0).map((issue) => {
      const { bg, hex } = SEV_COLORS[issue.severity] || SEV_COLORS.Low;
      
      const hoverMd = [
        `**[${issue.severity}] ${issue.type}**`,
        `_${issue.explanation}_`,
        '',
        `***Fix***: \n\`\`\`${language}\n${issue.fix}\n\`\`\``
      ].join('\n');

      return {
        range: new monacoInstance.Range(issue.line, 1, issue.line, 1),
        options: {
          isWholeLine: true,
          className: bg,
          glyphMarginClassName: 'text-[10px] flex items-center justify-center font-bold',
          glyphMarginHoverMessage: { value: `**${issue.severity}** issue` },
          hoverMessage: { value: hoverMd },
          minimap: { color: hex, position: 1 },
          overviewRuler: { color: hex, position: 4 },
        },
      };
    });

    decorationsRef.current = editor.deltaDecorations(oldIds, newDecorations);
  };

  // Re-apply decorations when issues change
  React.useEffect(() => {
    if (editorRef.current && monaco) {
      applyDecorations(editorRef.current, monaco, issues);
    }
  }, [issues, monaco, language]);

  const monacoLang = language === 'javascript' ? 'javascript' : language === 'python' ? 'python' : 'java';

  return (
    <div className="relative flex-1 overflow-hidden rounded-lg border border-shield-border bg-shield-surface">
      {/* Editor toolbar */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-shield-border bg-shield-card/50">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/60" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/60" />
            <span className="w-3 h-3 rounded-full bg-green-500/60" />
          </div>
          <span className="text-xs text-[#64748b] font-mono ml-2">
            main.{language === 'javascript' ? 'js' : language === 'python' ? 'py' : 'java'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {issues.length > 0 && (
            <span className="text-xs font-mono text-white bg-shield-card px-2 py-0.5 rounded border border-shield-border">
              <span className="text-red-400 font-bold">{issues.length}</span> vulnerabilities
            </span>
          )}
          <span className="text-xs text-[#334155] font-mono">
            {code.split('\n').length} lines
          </span>
        </div>
      </div>

      <Editor
        height="100%"
        language={monacoLang}
        value={code}
        onChange={(val) => onChange(val || '')}
        onMount={handleEditorDidMount}
        options={{
          fontSize: 13.5,
          fontFamily: '"JetBrains Mono", "Fira Code", monospace',
          fontLigatures: true,
          minimap: { enabled: true, scale: 1 },
          scrollBeyondLastLine: false,
          lineNumbers: 'on',
          glyphMargin: true,
          folding: true,
          lineDecorationsWidth: 8,
          renderLineHighlight: 'all',
          smoothScrolling: true,
          cursorBlinking: 'smooth',
          cursorSmoothCaretAnimation: 'on',
          tabSize: 2,
          wordWrap: 'on',
          padding: { top: 12, bottom: 12 },
          overviewRulerLanes: 2,
          scrollbar: {
            verticalScrollbarSize: 6,
            horizontalScrollbarSize: 6,
          },
        }}
      />
    </div>
  );
}
