/**
 * rules/error-leakage/ErrorLeakageRule.js
 *
 * Detects internal error details being returned to clients.
 * Exposing stack traces, error messages, or exception details to users
 * helps attackers understand system internals and craft targeted attacks.
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  // ── JavaScript / Node.js ──────────────────────────────────────────────────
  {
    regex: /res\.(?:send|json|end)\s*\([^)]*err(?:or)?\.(?:message|stack|name)\b/,
    type: 'Error Leakage — Stack Trace in Response',
    severity: 'Medium',
    explanation:
      'err.message or err.stack is being sent directly to the client. ' +
      'This exposes internal implementation details such as file paths, library versions, and system layout.',
    fix:
      'Return a generic error message to the client and log the details server-side:\n' +
      '  logger.error(err);\n' +
      '  res.status(500).json({ error: "Internal server error" });',
    confidence: 'High',
  },
  {
    regex: /res\.(?:send|json)\s*\(\s*\{\s*[^}]*(?:stack|trace|error|exception)\s*:\s*err/,
    type: 'Error Leakage — Exception Object in Response',
    severity: 'Medium',
    explanation:
      'An error/exception object is being included as a JSON field in the HTTP response, ' +
      'leaking internal details to the caller.',
    fix:
      'Never include raw error objects in responses:\n' +
      '  res.status(500).json({ error: "Something went wrong" });  // safe\n' +
      '  logger.error({ err }, "Request failed");                   // internal log',
    confidence: 'High',
  },
  {
    regex: /next\s*\(\s*err\s*\)/,
    type: 'Error Forwarded to Global Handler',
    severity: 'Low',
    explanation:
      'Passing the raw error to next() will expose it if the global error handler sends stack traces. ' +
      'Verify that your error handler does NOT forward err.stack to clients in production.',
    fix:
      'Ensure your error handler sanitizes the response:\n' +
      '  app.use((err, req, res, next) => {\n' +
      '    logger.error(err);\n' +
      '    res.status(500).json({ error: "Internal server error" });\n' +
      '  });',
    confidence: 'Low',
  },
  // ── Python / Flask ─────────────────────────────────────────────────────────
  {
    regex: /return\s+(?:jsonify|make_response|str)\s*\([^)]*(?:traceback|exception|exc_info|format_exc|str\s*\(\s*e\b)/,
    type: 'Error Leakage — Traceback in Response',
    severity: 'Medium',
    explanation:
      'A Python traceback or exception message is being returned in the HTTP response. ' +
      'This reveals internal file paths and library details.',
    fix:
      'Log the traceback internally and return a generic message:\n' +
      '  import traceback, logging\n' +
      '  logging.error(traceback.format_exc())\n' +
      '  return jsonify({"error": "Internal server error"}), 500',
    confidence: 'High',
  },
  {
    regex: /(?:print|logging\.(?:error|exception))\s*\(\s*traceback\.format_exc\s*\(\s*\)/,
    type: 'Traceback Logged (Review Needed)',
    severity: 'Low',
    explanation:
      'Traceback is logged — ensure it is not also forwarded to clients or exposed via debug mode.',
    fix:
      'Keep DEBUG=False in production and ensure Flask error pages do not show stack traces:\n' +
      '  app.config["DEBUG"] = False\n' +
      '  app.config["PROPAGATE_EXCEPTIONS"] = False',
    confidence: 'Low',
  },
  // ── Java / Servlets / Spring ───────────────────────────────────────────────
  {
    regex: /e\.printStackTrace\s*\(\s*\)/,
    type: 'Error Leakage — printStackTrace in Servlet',
    severity: 'Medium',
    explanation:
      'e.printStackTrace() writes stack traces to the console/server log. In some servlet configurations ' +
      'this output is forwarded to the HTTP response, revealing internal details.',
    fix:
      'Use a structured logger instead:\n' +
      '  log.error("Request failed", e);  // SLF4J\n' +
      'And return a sanitized response:\n' +
      '  response.sendError(500, "Internal server error");',
    confidence: 'Medium',
  },
  {
    regex: /response\s*\.\s*(?:getWriter|sendError)\s*\([^)]*(?:e\.getMessage|e\.toString|ex\.getMessage)/,
    type: 'Error Leakage — Exception Message in HTTP Response',
    severity: 'High',
    explanation:
      'An exception message is written directly to the HTTP response. ' +
      'This exposes internal details to the client.',
    fix:
      'Return only a safe, generic message:\n' +
      '  response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal error");',
    confidence: 'High',
  },
];

class ErrorLeakageRule extends BaseRule {
  constructor() {
    super('LEAKAGE', 'Error Leakage');
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

module.exports = ErrorLeakageRule;
