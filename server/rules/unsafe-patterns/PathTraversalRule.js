/**
 * rules/unsafe-patterns/PathTraversalRule.js
 *
 * Detects file operations that accept user-supplied paths,
 * enabling path traversal (../) attacks.
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  {
    // Node.js / Python file ops with concatenated or request-bound path
    regex: /(?:readFile|writeFile|createReadStream|open|fopen|FileReader|readFileSync)\s*\([^)]*(?:\+|req\.|request\.|params\.|query\.|body\.)/,
    type: 'Path Traversal',
    severity: 'High',
    explanation:
      'File operation with user-supplied path — an attacker can use ../ sequences to read or overwrite arbitrary files.',
    fix:
      'Use path.resolve() then verify the result starts within your allowed base directory:\n' +
      '  const safe = path.resolve(BASE, name);\n' +
      '  if (!safe.startsWith(BASE)) throw new Error("Traversal blocked");',
  },
];

class PathTraversalRule extends BaseRule {
  constructor() {
    super('UNSAFE_PATH', 'Path Traversal');
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

module.exports = PathTraversalRule;
