/**
 * analyzers/index.js — Static Analysis Orchestrator (v2 — SAST Enhanced)
 *
 * Pipeline:
 *   InputParser  →  [ Rule Engine + Taint Engine ]  →  Reporter
 *
 * The public API (runStaticAnalysis) is unchanged — all callers require
 * zero modification.
 *
 * Adding new capabilities:
 *   - New rule:  add class to server/rules/ and register in server/rules/index.js
 *   - New taint source:  add to server/taint/sources.js
 *   - New taint sink:    add to server/taint/sinks.js
 *
 * @typedef {{
 *   id: string,
 *   type: string,
 *   severity: 'Critical' | 'High' | 'Medium' | 'Low',
 *   confidence: 'High' | 'Medium' | 'Low',
 *   line: number,
 *   snippet: string,
 *   explanation: string,
 *   fix: string,
 *   source: string
 * }} Issue
 */

'use strict';

const InputParser  = require('../parser');
const { runRules } = require('../rules');
const TaintEngine  = require('../taint/TaintEngine');
const Reporter     = require('../reporter');

const parser      = new InputParser();
const taintEngine = new TaintEngine();
const reporter    = new Reporter();

/**
 * Run all security rules + taint analysis against the provided source code.
 *
 * @param {string} code      Raw source code string
 * @param {string} language  'javascript' | 'python' | 'java'
 * @returns {Issue[]}        Deduplicated, severity-sorted issues
 */
function runStaticAnalysis(code, language) {
  const context      = parser.parse(code, language);
  const ruleIssues   = runRules(context);
  const taintIssues  = taintEngine.analyze(context);

  return reporter.report([...ruleIssues, ...taintIssues]);
}

module.exports = { runStaticAnalysis };
