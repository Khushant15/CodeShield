/**
 * rules/unsafe-patterns/CryptoRule.js
 *
 * Detects weak cryptography: broken hashes (MD5/SHA-1), insecure randomness,
 * and TLS certificate verification bypass.
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  {
    regex: /rejectUnauthorized\s*:\s*false/,
    type: 'TLS Verification Disabled',
    severity: 'High',
    explanation:
      'Disabling TLS certificate verification makes every HTTPS connection vulnerable to man-in-the-middle attacks.',
    fix: 'Remove rejectUnauthorized: false. Fix the certificate problem properly (update CA bundle, use a valid cert).',
  },
  {
    regex: /verify\s*=\s*False/,
    type: 'TLS Verification Disabled (Python)',
    severity: 'High',
    explanation:
      'requests.get(url, verify=False) disables SSL/TLS validation — MITM attacks are trivially possible.',
    fix: 'Remove verify=False. Provide the CA bundle path if needed: verify="/path/to/ca-bundle.crt"',
  },
  {
    regex: /(?:md5|sha1|MD5|SHA1)\s*(?:\(|\.)/,
    type: 'Weak Cryptographic Hash',
    severity: 'Medium',
    explanation:
      'MD5 and SHA-1 are cryptographically broken — collisions are computationally feasible.',
    fix: 'Use SHA-256/SHA-3 for integrity checks. For passwords, use bcrypt, scrypt, or Argon2.',
  },
  {
    regex: /Math\.random\s*\(\s*\)/,
    type: 'Insecure Randomness',
    severity: 'Medium',
    explanation:
      'Math.random() is not cryptographically secure. Do not use it for tokens, passwords, or session IDs.',
    fix: 'Use crypto.randomBytes(32) in Node.js or crypto.getRandomValues() in the browser.',
  },
];

class CryptoRule extends BaseRule {
  constructor() {
    super('UNSAFE_CRYPTO', 'Weak Cryptography');
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

module.exports = CryptoRule;
