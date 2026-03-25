/**
 * rules/unsafe-patterns/DeserializationRule.js
 *
 * Detects insecure deserialization in Python (pickle, yaml) and Java (ObjectInputStream).
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  {
    regex: /pickle\.loads?\s*\(/,
    type: 'Insecure Deserialization (pickle)',
    severity: 'High',
    explanation:
      'pickle.load() on untrusted data leads to arbitrary Python code execution.',
    fix: 'Never deserialize untrusted data with pickle. Use JSON or a validated schema (Pydantic, marshmallow).',
  },
  {
    regex: /yaml\.load\s*\([^)]*(?!SafeLoader)/,
    type: 'Insecure Deserialization (PyYAML)',
    severity: 'High',
    explanation: 'yaml.load() without SafeLoader can execute arbitrary Python code via YAML tags.',
    fix: 'Use yaml.safe_load() instead of yaml.load().',
  },
  {
    regex: /ObjectInputStream|readObject\s*\(\s*\)/,
    type: 'Insecure Deserialization (Java)',
    severity: 'High',
    explanation:
      'Java ObjectInputStream deserialization of untrusted data can lead to RCE via gadget chains.',
    fix: 'Use a serialization filter (JEP 290), or replace with JSON (Jackson, Gson) for data exchange.',
  },
];

class DeserializationRule extends BaseRule {
  constructor() {
    super('UNSAFE_DESER', 'Insecure Deserialization');
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

module.exports = DeserializationRule;
