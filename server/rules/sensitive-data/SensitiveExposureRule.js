/**
 * rules/sensitive-data/SensitiveExposureRule.js
 *
 * Detects APIs and functions that return sensitive data to clients
 * without field-level filtering (e.g., returning full user objects
 * including passwords, tokens, emails).
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  // ── Full object serialization without filtering ───────────────────────────
  {
    regex: /res\.(?:json|send)\s*\(\s*\b(?:users?|accounts?|records?|rows?|results?|data)\b\s*\)/,
    type: 'Sensitive Data Exposure — Unfiltered Response',
    severity: 'High',
    explanation:
      'Sending an entire database result set or model object to the client may expose sensitive fields ' +
      'such as passwords, tokens, or personal data.',
    fix:
      'Whitelist only the fields the client should receive:\n' +
      '  // JavaScript: explicit projection\n' +
      '  res.json(users.map(u => ({ id: u.id, name: u.name, email: u.email })));\n\n' +
      '  // Mongoose: select("-password -token")\n' +
      '  // Sequelize: attributes: ["id", "name"]',
    confidence: 'Medium',
  },
  {
    regex: /return\s+jsonify\s*\(\s*\b(?:user|users|account|data|records?)\b\s*\)/,
    type: 'Sensitive Data Exposure — Unfiltered Response',
    severity: 'High',
    explanation:
      'Returning a full ORM/database object via jsonify() may expose sensitive fields (passwords, tokens) to clients.',
    fix:
      'Filter fields before returning:\n' +
      '  return jsonify({"id": user.id, "name": user.name})',
    confidence: 'Medium',
  },
  // ── Sensitive field names in response output ───────────────────────────────
  {
    regex: /(?:res\.json|res\.send|jsonify|render_template|response\.write)\s*\([^)]*(?:password|passwd|secret|api_key|apikey|token|ssn|credit_card|dob|date_of_birth)\b/i,
    type: 'Sensitive Field Returned to Client',
    severity: 'High',
    explanation:
      'A response includes a field with a sensitive name (password, token, ssn, etc.). ' +
      'This data should be excluded from client-facing responses.',
    fix:
      'Explicitly omit sensitive fields before serializing:\n' +
      '  const { password, token, ...safe } = user;\n' +
      '  res.json(safe);\n\n' +
      '  // Or use DTO/serializer patterns that whitelist allowed fields.',
    confidence: 'High',
  },
  // ── Returning all records without pagination/filtering ─────────────────────
  {
    regex: /\b(?:User|Account|Admin|Employee)\.find(?:All|Many)?\s*\(\s*\{\s*\}\s*\)/,
    type: 'Mass Data Exposure — All Records Returned',
    severity: 'Medium',
    explanation:
      'A query fetches all records from a user/account table with no filter. ' +
      'API endpoints that return all users can expose PII at scale.',
    fix:
      'Add filtering, pagination, and field projection:\n' +
      '  User.findAll({ where: { active: true }, attributes: ["id","name"], limit: 50, offset })',
    confidence: 'Medium',
  },
  {
    regex: /SELECT\s+\*\s+FROM\s+(?:users|accounts|employees|admins|customers)\b/i,
    type: 'Mass Data Exposure — SELECT * on Sensitive Table',
    severity: 'Medium',
    explanation: 'SELECT * on users/accounts returns all columns including passwords and tokens.',
    fix:
      'Select only necessary columns:\n' +
      '  SELECT id, name, email FROM users WHERE ...',
    confidence: 'Medium',
  },
  // ── Password/token included in payload without hashing check ───────────────
  {
    regex: /JSON\.stringify\s*\(\s*\b(?:user|users|account|session)\b\s*\)/,
    type: 'Sensitive Data Exposure — Full Object Serialized',
    severity: 'Medium',
    explanation:
      'JSON.stringify on a user/session object will serialize all properties, potentially including sensitive fields.',
    fix:
      'Create a safe copy with only allowed fields before stringifying:\n' +
      '  const safeUser = { id: user.id, name: user.name };\n' +
      '  JSON.stringify(safeUser);',
    confidence: 'Low',
  },
];

class SensitiveExposureRule extends BaseRule {
  constructor() {
    super('EXPOSURE', 'Sensitive Data Exposure');
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

      for (const { regex, type, severity, explanation, fix, confidence } of PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          issues.push(
            this._buildIssue(type, severity, idx + 1, trimmed, explanation, fix, confidence)
          );
          break;
        }
      }
    });

    return issues;
  }
}

module.exports = SensitiveExposureRule;
