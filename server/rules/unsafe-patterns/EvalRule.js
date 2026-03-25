/**
 * rules/unsafe-patterns/EvalRule.js
 *
 * Detects dangerous code execution via eval() and new Function().
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  {
    regex: /\beval\s*\(/,
    type: 'Dangerous eval()',
    severity: 'High',
    explanation:
      'eval() compiles and executes any string as code. With user-controlled input this is Remote Code Execution.',
    fix: 'Replace eval() with JSON.parse() for data, or refactor dynamic dispatch using a lookup map.',
  },
  {
    regex: /new\s+Function\s*\(/,
    type: 'Unsafe Function Constructor',
    severity: 'High',
    explanation:
      'new Function(string) is eval() with extra steps — it runs arbitrary code at runtime.',
    fix: 'Use predefined function references. Never build functions from strings at runtime.',
  },
  {
    regex: /setTimeout\s*\(\s*[`'""]|setInterval\s*\(\s*[`'""]/,
    type: 'Implicit eval via setTimeout/setInterval',
    severity: 'Medium',
    explanation: 'Passing a string to setTimeout/setInterval is equivalent to calling eval().',
    fix: 'Always pass a function: setTimeout(() => myFn(arg), delay)',
  },
];

class EvalRule extends BaseRule {
  constructor() {
    super('UNSAFE_EVAL', 'Dangerous Eval Usage');
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

module.exports = EvalRule;
