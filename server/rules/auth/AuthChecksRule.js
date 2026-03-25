/**
 * rules/auth/AuthChecksRule.js
 *
 * Detects routes/endpoints that access sensitive data or operations
 * but lack authentication/authorization guards nearby.
 *
 * Strategy:
 *   1. Find route definitions (Express, Flask, Java Servlets/Spring)
 *   2. Look for sensitive data access within ±15 lines of the route
 *   3. If no auth guard is found within that window → flag it
 */

'use strict';

const BaseRule = require('../base/BaseRule');

// ── Route definition patterns ─────────────────────────────────────────────────
const ROUTE_PATTERNS = {
  javascript: [
    /(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"`]/,
    /express\.Router\s*\(\s*\)/,
  ],
  python: [
    /@(?:app|blueprint|bp)\.route\s*\(/,
    /@(?:app|blueprint|bp)\.(?:get|post|put|patch|delete)\s*\(/,
  ],
  java: [
    /@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*[\(@]/,
    /void\s+do(?:Get|Post|Put|Delete)\s*\(/,
  ],
};

// ── Auth guard patterns ───────────────────────────────────────────────────────
const AUTH_PATTERNS = {
  javascript: [
    /\b(?:isAuthenticated|requireAuth|verifyToken|checkAuth|authenticate|authorize)\b/,
    /\bpassport\s*\.\s*(?:authenticate|authorize)\b/,
    /\bjwt\.verify\b/,
    /\b(?:authMiddleware|tokenMiddleware|sessionMiddleware)\b/,
    /req\s*\.\s*(?:user|session|isAuthenticated)\b/,
    /\bif\s*\(!?\s*req\s*\.\s*(?:user|session|isAuthenticated)/,
  ],
  python: [
    /@login_required\b/,
    /@jwt_required\b/,
    /@token_required\b/,
    /\bcurrent_user\s*\.\s*is_authenticated\b/,
    /\bverify_jwt_in_request\s*\(\)/,
    /\bif\s+not\s+current_user\b/,
  ],
  java: [
    /SecurityContextHolder\s*\.\s*getContext\s*\(\)/,
    /@PreAuthorize\b/,
    /@Secured\b/,
    /\bHttpSession\s+session\b/,
    /\bgetSession\s*\(\s*false\s*\)/,
    /\b(?:isAuthenticated|isAuthorized|checkPermission)\s*\(/,
  ],
};

// ── Sensitive-data access patterns ────────────────────────────────────────────
const SENSITIVE_PATTERNS = [
  /\b(?:user|users|account|accounts|admin|password|token|auth|profile|credential|secret)\b/i,
  /\b(?:getAllUsers|findAll|find\(\{\}\)|db\.query|cursor\.execute)\b/,
  /\b(?:DELETE|DROP|TRUNCATE|UPDATE|INSERT)\b/i,
  /\b(?:role|permission|privilege)\b/i,
];

const WINDOW = 15; // lines before/after the route definition to inspect

class AuthChecksRule extends BaseRule {
  constructor() {
    super('AUTH', 'Missing Authentication Check');
  }

  /**
   * @param {import('../base/BaseRule').ParsedContext} context
   * @returns {import('../base/BaseRule').Issue[]}
   */
  analyze(context) {
    const { lines, language } = context;
    const issues   = [];
    const routePats = ROUTE_PATTERNS[language]  || [];
    const authPats  = AUTH_PATTERNS[language]   || [];

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (this._isComment(trimmed)) return;

      // Check if this line is a route definition
      const isRoute = routePats.some(p => p.test(line));
      if (!isRoute) return;

      // Define inspection window around the route
      const start = Math.max(0, idx - WINDOW);
      const end   = Math.min(lines.length - 1, idx + WINDOW);
      const window = lines.slice(start, end + 1).join('\n');

      // Check: does the window access sensitive data?
      const touchesSensitive = SENSITIVE_PATTERNS.some(p => p.test(window));
      if (!touchesSensitive) return;

      // Check: does the window have an auth guard?
      const hasAuth = authPats.some(p => p.test(window));
      if (hasAuth) return;

      issues.push(
        this._buildIssue(
          'Missing Authentication / Authorization',
          'High',
          idx + 1,
          trimmed,
          'A route that accesses sensitive data or operations appears to lack authentication or authorization middleware. ' +
          'Unauthenticated callers may access protected resources.',
          this._getFix(language),
          'Medium'
        )
      );
    });

    return issues;
  }

  _getFix(language) {
    const fixes = {
      javascript:
        'Add authentication middleware before your handler:\n' +
        '  // Express + JWT:\n' +
        '  router.get("/users", verifyToken, (req, res) => { ... })\n\n' +
        '  // Passport:\n' +
        '  router.get("/profile", passport.authenticate("jwt"), (req, res) => { ... })',
      python:
        'Protect the route with a decorator:\n' +
        '  # Flask-Login:\n' +
        '  @login_required\n' +
        '  @app.route("/users")\n' +
        '  def get_users(): ...\n\n' +
        '  # Flask-JWT-Extended:\n' +
        '  @jwt_required()\n' +
        '  @app.route("/profile")\n' +
        '  def profile(): ...',
      java:
        'Add Spring Security annotations or session checks:\n' +
        '  @PreAuthorize("isAuthenticated()")\n' +
        '  @GetMapping("/users")\n' +
        '  public List<User> getUsers() { ... }\n\n' +
        '  // Or check session manually:\n' +
        '  HttpSession session = request.getSession(false);\n' +
        '  if (session == null) { response.sendError(401); return; }',
    };
    return fixes[language] || fixes.javascript;
  }
}

module.exports = AuthChecksRule;
