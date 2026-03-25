/**
 * rules/secrets/SecretsRule.js
 *
 * Layer-2 detection: generic secret-named variable heuristic.
 * Fires when a variable with a sensitive name (password, api_key, token, …)
 * is assigned a non-trivial, non-placeholder string literal.
 */

'use strict';

const BaseRule = require('../base/BaseRule');

// Sensitive variable names (covers abbreviations like pw, tk, key)
const SECRET_VAR_RE =
  /\b(?:password|passwd|passw|pass|pwd|pw|secret|api[_-]?key|apikey|api[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|id[_-]?token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|db[_-]?pass(?:word)?|database[_-]?pass|conn(?:ection)?[_-]?str(?:ing)?|credentials?|token|authkey|encryption[_-]?key|signing[_-]?key|hmac[_-]?secret)\s*(?:=|:)/gi;

// Quoted string value (min 4 chars)
const STRING_VALUE_RE = /(?:["'`])([^"'`\n]{4,})(?:["'`])/;

// Values that look like placeholders — skip
const PLACEHOLDER_RE =
  /^(?:your[_-]?|my[_-]?|sample[_-]?|example[_-]?|replace[_-]?|change[_-]?me|xxx+|test[_-]?|dummy|placeholder|\$\{|<[^>]+>|\.\.\.)/i;

// References to env vars — definitely not hardcoded
const ENV_REF_RE = /process\.env|os\.environ|getenv|System\.getenv/i;

class SecretsRule extends BaseRule {
  constructor() {
    super('SECRET', 'Hardcoded Credential');
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
      if (this._isComment(trimmed)) return;
      if (/^\s*(?:import|require|from|use)\s/.test(trimmed)) return;

      SECRET_VAR_RE.lastIndex = 0;
      if (!SECRET_VAR_RE.test(line)) return;

      const match = STRING_VALUE_RE.exec(line);
      if (!match) return;

      const val = match[1].trim();
      if (val.length < 4) return;
      if (PLACEHOLDER_RE.test(val)) return;
      if (ENV_REF_RE.test(line)) return;

      const redacted = trimmed
        .replace(/(['"`])[^'"`]{4,}(['"`])/g, '$1[REDACTED]$2')
        .slice(0, 200);

      issues.push(
        this._buildIssue(
          'Hardcoded Credential',
          'High',
          idx + 1,
          redacted,
          'A credential is hardcoded as a string literal. Hardcoded secrets in source code are exposed ' +
          'via version control, logs, and process memory.',
          'Use environment variables:\n' +
          '  const secret = process.env.SECRET_KEY;             // Node.js\n' +
          '  secret = os.environ.get("SECRET_KEY")              // Python\n' +
          '  String secret = System.getenv("SECRET_KEY");       // Java'
        )
      );
    });

    return issues;
  }
}

module.exports = SecretsRule;
