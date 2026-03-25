/**
 * rules/unsafe-patterns/MiscRule.js
 *
 * Miscellaneous unsafe patterns:
 *   - Prototype pollution
 *   - Sensitive data logging
 *   - Open redirect
 *   - XXE (XML External Entity) — Java
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  {
    regex: /__proto__\s*[\[=]|constructor\s*\[\s*['"]prototype/,
    type: 'Prototype Pollution',
    severity: 'High',
    explanation:
      'Assigning to __proto__ or constructor.prototype poisons the prototype chain for ALL objects in the process.',
    fix: 'Validate/whitelist keys before merging objects. Use Object.create(null) for data dictionaries.',
  },
  {
    regex: /console\.(?:log|info|debug|warn|error)\s*\([^)]*(?:password|secret|token|apikey|api_key|auth)/i,
    type: 'Sensitive Data Logged',
    severity: 'Low',
    explanation:
      'Logging secrets or credentials exposes them in log files, monitoring dashboards, and process output.',
    fix:
      'Remove logging of sensitive values. Use a redacted placeholder:\n' +
      '  logger.info("User authenticated", { userId }); // never log the token itself',
  },
  {
    regex: /res\.redirect\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/,
    type: 'Open Redirect',
    severity: 'Medium',
    explanation:
      'Redirecting to a URL taken directly from user input enables phishing attacks via your trusted domain.',
    fix: 'Validate the redirect target against an allowlist of safe domains/paths.',
  },
  {
    regex: /(?:DocumentBuilder|SAXParser|XMLReader).*(?:parse|newInstance)\s*\(/,
    type: 'Potential XXE (XML External Entity)',
    severity: 'Medium',
    explanation:
      'Java XML parsers enable external entity processing by default — attackers can use XXE to read local files.',
    fix:
      'Disable external entities:\n' +
      '  factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)',
  },
];

class MiscRule extends BaseRule {
  constructor() {
    super('UNSAFE_MISC', 'Miscellaneous Unsafe Pattern');
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

      for (const { regex, type, severity, explanation, fix } of PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          issues.push(this._buildIssue(type, severity, idx + 1, trimmed, explanation, fix));
          break;
        }
      }
    });

    return issues;
  }
}

module.exports = MiscRule;
