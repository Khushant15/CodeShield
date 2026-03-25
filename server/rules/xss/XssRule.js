/**
 * rules/xss/XssRule.js
 *
 * Detects Cross-Site Scripting (XSS) vulnerabilities.
 * Covers innerHTML, outerHTML, document.write, dangerouslySetInnerHTML,
 * jQuery .html(), location.href, Python Markup/mark_safe, and Java PrintWriter.
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  {
    // innerHTML = non-literal value
    regex: /\.innerHTML\s*=\s*(?![`'"]\s*[`'"]|[`'"]<(?:div|span|p|b|i|br)>)/g,
    severity: 'High',
    note: 'innerHTML assignment with a non-literal value — attacker-controlled content can inject executable scripts.',
    fix: 'Use .textContent for plain text.\nFor HTML, sanitize first:\n  element.innerHTML = DOMPurify.sanitize(untrustedHTML);',
  },
  {
    regex: /\.outerHTML\s*=\s*(?![`'"])/g,
    severity: 'High',
    note: 'outerHTML assignment with a dynamic value is an XSS vector.',
    fix: 'Avoid outerHTML with dynamic content. Rebuild the element with DOM APIs (createElement, appendChild).',
  },
  {
    regex: /document\.write\s*\(/g,
    severity: 'High',
    note: 'document.write() with dynamic content is a classic XSS sink and blocks the HTML parser.',
    fix: 'Replace with:\n  const el = document.getElementById("target");\n  el.textContent = safeValue;',
  },
  {
    regex: /document\.writeln\s*\(/g,
    severity: 'High',
    note: 'document.writeln() is deprecated and an XSS risk.',
    fix: 'Use safe DOM manipulation instead.',
  },
  {
    regex: /insertAdjacentHTML\s*\(\s*['"][^'"]+['"]\s*,/g,
    severity: 'High',
    note: 'insertAdjacentHTML with any non-literal second argument can inject scripts.',
    fix: 'Use insertAdjacentText for plain text.\nFor HTML, sanitize first with DOMPurify.',
  },
  {
    regex: /dangerouslySetInnerHTML\s*=\s*\{/g,
    severity: 'Medium',
    note: "React's dangerouslySetInnerHTML bypasses its XSS protection — the HTML must be sanitized before use.",
    fix: 'Sanitize before rendering:\n  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}',
  },
  {
    // jQuery .html() with non-literal argument
    regex: /\$\s*\([^)]+\)\s*\.html\s*\(\s*(?!\s*[`'"])/g,
    severity: 'High',
    note: 'jQuery .html() with a variable argument injects raw HTML — XSS if user-controlled.',
    fix: 'Use .text() for plain text content.\nFor HTML: $(el).html(DOMPurify.sanitize(value))',
  },
  {
    // React __html without sanitization
    regex: /__html\s*:\s*(?!DOMPurify|sanitize)/g,
    severity: 'Medium',
    note: '__html property set without apparent sanitization — ensure content is safe before rendering.',
    fix: 'Always sanitize: { __html: DOMPurify.sanitize(content) }',
  },
  {
    // location.href / location.replace with dynamic value
    regex: /(?:location\.href|location\.replace|window\.location)\s*=\s*(?![`'"](?:https?:\/\/|\/(?!\/))[^`'" ])/g,
    severity: 'Medium',
    note: 'Assigning a dynamic value to location.href can enable open redirect attacks or javascript: URL execution.',
    fix: 'Validate URLs against an allowlist of known-safe origins before redirecting.',
  },
  {
    // Python/Jinja Markup() or mark_safe() without obvious sanitization
    regex: /(?:Markup|mark_safe)\s*\(\s*(?![`'"]<)/g,
    severity: 'High',
    note: 'Marking untrusted HTML as safe bypasses template auto-escaping — potential server-side XSS.',
    fix: "Only call Markup()/mark_safe() on strings that have been explicitly sanitized (e.g., bleach.clean()).",
  },
  {
    // Java: PrintWriter write/print with request params
    regex: /(?:getWriter|PrintWriter)\s*\(\s*\).*\.(?:print|write|println)\s*\([^)]*(?:req\.|request\.|getParameter|getHeader)/g,
    severity: 'High',
    note: 'Writing HTTP request data directly to the response without encoding causes reflected XSS.',
    fix: 'Encode output:\n  response.getWriter().print(StringEscapeUtils.escapeHtml4(userInput));',
  },
];

class XssRule extends BaseRule {
  constructor() {
    super('XSS', 'Cross-Site Scripting (XSS)');
  }

  /**
   * @param {import('../base/BaseRule').ParsedContext} context
   * @returns {import('../base/BaseRule').Issue[]}
   */
  analyze(context) {
    const { lines } = context;
    const issues = [];

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed || /^\s*(?:\/\/|#|\*)\s/.test(trimmed)) return;

      for (const { regex, severity, note, fix } of PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          issues.push(
            this._buildIssue('Cross-Site Scripting (XSS)', severity, idx + 1, trimmed, note, fix)
          );
          break;
        }
      }
    });

    return issues;
  }
}

module.exports = XssRule;
