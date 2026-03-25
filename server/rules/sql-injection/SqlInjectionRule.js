/**
 * rules/sql-injection/SqlInjectionRule.js
 *
 * Detects SQL injection vulnerabilities across JavaScript, Python, and Java.
 *
 * Enhancements over v1:
 *   - Python f-string in SQL context (f"SELECT ... {var}")
 *   - Safe-pattern whitelist: parameterized queries, ORMs, prepared statements
 *   - Confidence scoring: direct user-input reference = High, general concat = Medium
 */

'use strict';

const BaseRule = require('../base/BaseRule');

// ── Safe pattern allowlist — skip lines that match these ─────────────────────
// These are parameterized / ORM patterns that are NOT injection risks
const SAFE_PATTERNS = [
  /\$\d+/,                             // node-postgres: $1, $2
  /\?\s*(?:,|\))/,                     // positional placeholders: ?, ?)
  /\.setString\s*\(/,                  // Java PreparedStatement.setString
  /\.setInt\s*\(/,                     // Java PreparedStatement.setInt
  /Text\s*\(\s*['"`]/,                 // SQLAlchemy text() with literal
  /\bsession\.query\s*\(\s*\w+\s*\)/,  // SQLAlchemy ORM session.query(Model)
  /\bfindById\s*\(|findByPk\s*\(|findOne\s*\(\s*\{/, // Sequelize ORM
  /\bModel\.\w+\s*\(\s*\{/,           // ActiveRecord / Mongoose ORM pattern
  /cursor\.execute\s*\(\s*['"`][^'"]*['"`]\s*,\s*\(/, // Python parameterized tuple
  /cursor\.execute\s*\(\s*['"`][^'"]*['"`]\s*,\s*\[/, // Python parameterized list
];

const PATTERNS = [
  // Python f-strings in SQL context NEW
  {
    regex: /f['"`].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN|INTO)\b.*?\{[^}]+\}/gi,
    confidence: 'High',
    note: 'Python f-string with variable interpolation inside a SQL query — high-confidence SQL injection.',
  },
  // String/template literal containing SQL keyword + concatenation (JS)
  {
    regex: /[`'"].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN|INTO)\b.*?[`'"]\s*\+/gi,
    confidence: 'High',
    note: 'String concatenation inside a SQL literal.',
  },
  // Template literal with ${} in SQL context (JS)
  {
    regex: /(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN|INTO)\b[^;\n]{0,120}\$\{[^}]+\}/gi,
    confidence: 'High',
    note: 'Template literal interpolation inside a SQL query.',
  },
  // query/sql/stmt variable assigned with + concatenation
  {
    regex: /\b(?:query|sql|stmt|statement|qry|sqlStr|sqlString|sqlQuery)\b\s*[+]?=\s*[^\n]*\+\s*\w+/gi,
    confidence: 'Medium',
    note: 'SQL-named variable built via string concatenation.',
  },
  // Python % formatting in execute()
  {
    regex: /\.(?:execute|executemany)\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*[%+]|['"][^'"]*['"]\s*\.format\s*\()/gi,
    confidence: 'High',
    note: 'Python execute() with f-string, %-formatting, or .format() interpolation.',
  },
  // Java JDBC Statement + concatenation
  {
    regex: /\.(?:executeQuery|executeUpdate|execute)\s*\(\s*(?:"[^"]*"\s*\+|'[^']*'\s*\+|\w[\w.]*\s*\+)/gi,
    confidence: 'High',
    note: 'Java JDBC execute with string concatenation.',
  },
  // ORM raw() / query() with interpolation (JS)
  {
    regex: /\.(?:raw|query|from)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/gi,
    confidence: 'Medium',
    note: 'ORM raw query with interpolation.',
  },
  // Direct string build: "SELECT" + request variable
  {
    regex: /(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,80}\+\s*(?:req\.|request\.|params\.|query\.|body\.|user|input|\w+Id|\w+[Ii]nput|\w+[Pp]aram)/gi,
    confidence: 'High',
    note: 'SQL keyword directly concatenated with request/user input.',
  },
  // Python % formatting in SQL string
  {
    regex: /['"].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b.*?['"]\s*%\s*(?:\(|[a-zA-Z_])/gi,
    confidence: 'High',
    note: 'Python %-string formatting in SQL context.',
  },
];

const EXPLANATION =
  'User-controlled data is concatenated or interpolated directly into a SQL query. ' +
  'An attacker can manipulate the query to bypass authentication, exfiltrate data, or destroy the database.';

const FIX = {
  python:
    'Use parameterized queries:\n' +
    '  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n' +
    '  # SQLAlchemy:\n' +
    '  session.execute(text("SELECT * FROM t WHERE id = :id"), {"id": user_id})',
  java:
    'Use PreparedStatement:\n' +
    '  PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n' +
    '  ps.setString(1, userId);\n' +
    '  ResultSet rs = ps.executeQuery();',
  javascript:
    'Use parameterized queries:\n' +
    '  // node-postgres: db.query("SELECT * FROM users WHERE id = $1", [userId])\n' +
    '  // mysql2:        db.execute("SELECT * FROM users WHERE id = ?", [userId])\n' +
    '  // Sequelize:     User.findByPk(userId)',
};

class SqlInjectionRule extends BaseRule {
  constructor() {
    super('SQL', 'SQL Injection');
  }

  /**
   * @param {import('../base/BaseRule').ParsedContext} context
   * @returns {import('../base/BaseRule').Issue[]}
   */
  analyze(context) {
    const { lines, language } = context;
    const issues = [];
    const fix = FIX[language] || FIX.javascript;

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (this._isComment(trimmed)) return;

      // Skip lines that match safe parameterized/ORM patterns
      if (SAFE_PATTERNS.some(sp => sp.test(line))) return;

      for (const { regex, confidence, note } of PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          const fullExplanation = `${EXPLANATION}\nDetection: ${note}`;
          issues.push(
            this._buildIssue('SQL Injection', 'High', idx + 1, trimmed, fullExplanation, fix, confidence)
          );
          break;
        }
      }
    });

    return issues;
  }
}

module.exports = SqlInjectionRule;
