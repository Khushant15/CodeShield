/**
 * rules/index.js — Rule Registry (v2 — SAST Enhanced)
 *
 * Single place to register all security rules.
 * Adding a new rule:
 *   1. Create your class in server/rules/<category>/MyRule.js
 *   2. Import it here + add an instance to RULES
 *   3. Done — no other files change.
 */

'use strict';

// ── SQL Injection ────────────────────────────────────────────────────────────
const SqlInjectionRule        = require('./sql-injection/SqlInjectionRule');

// ── Cross-Site Scripting ─────────────────────────────────────────────────────
const XssRule                 = require('./xss/XssRule');

// ── Secrets & Credentials ────────────────────────────────────────────────────
const VendorSecretsRule       = require('./secrets/VendorSecretsRule');
const SecretsRule             = require('./secrets/SecretsRule');

// ── Unsafe Code Patterns ─────────────────────────────────────────────────────
const EvalRule                = require('./unsafe-patterns/EvalRule');
const CommandInjectionRule    = require('./unsafe-patterns/CommandInjectionRule');
const DeserializationRule     = require('./unsafe-patterns/DeserializationRule');
const CryptoRule              = require('./unsafe-patterns/CryptoRule');
const PathTraversalRule       = require('./unsafe-patterns/PathTraversalRule');
const MiscRule                = require('./unsafe-patterns/MiscRule');

// ── SAST Enhancements ────────────────────────────────────────────────────────
const AuthChecksRule          = require('./auth/AuthChecksRule');
const SensitiveExposureRule   = require('./sensitive-data/SensitiveExposureRule');
const ErrorLeakageRule        = require('./error-leakage/ErrorLeakageRule');

/**
 * Ordered registry of all active security rules.
 * @type {import('./base/BaseRule')[]}
 */
const RULES = [
  // Data injection
  new SqlInjectionRule(),
  new XssRule(),

  // Secrets — vendor first (high precision), heuristic second
  new VendorSecretsRule(),
  new SecretsRule(),

  // Dangerous execution
  new EvalRule(),
  new CommandInjectionRule(),
  new DeserializationRule(),

  // Crypto & transport
  new CryptoRule(),

  // File & memory
  new PathTraversalRule(),

  // Miscellaneous (prototype pollution, logging, redirect, XXE)
  new MiscRule(),

  // ── SAST enhancements (run after pattern rules) ──────────────────────────
  new AuthChecksRule(),       // unprotected routes accessing sensitive data
  new SensitiveExposureRule(), // unfiltered DB objects/sensitive fields in responses
  new ErrorLeakageRule(),     // stack traces / error messages exposed to clients
];

/**
 * Run all registered rules against the provided parsed context.
 *
 * @param {import('./base/BaseRule').ParsedContext} context
 * @returns {import('./base/BaseRule').Issue[]}    flat list (unsorted)
 */
function runRules(context) {
  const allIssues = [];

  for (const rule of RULES) {
    rule.reset();
    try {
      const found = rule.analyze(context);
      allIssues.push(...found);
    } catch (err) {
      console.error(`[RuleEngine] Rule "${rule.name}" threw:`, err.message);
    }
  }

  return allIssues;
}

module.exports = { runRules, RULES };
