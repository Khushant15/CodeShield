/**
 * rules/base/BaseRule.js
 *
 * Abstract base class that every security rule must extend.
 *
 * Severity tiers: Critical → High → Medium → Low
 * Confidence:     High | Medium | Low  (detection certainty)
 * Source:         'rule' | 'taint' | 'ai'
 *
 * @typedef {Object} ParsedContext
 * @property {string}   code
 * @property {string}   language
 * @property {string}   filename
 * @property {string[]} lines
 * @property {number}   lineCount
 *
 * @typedef {Object} Issue
 * @property {string} id
 * @property {string} type
 * @property {'Critical'|'High'|'Medium'|'Low'} severity
 * @property {'High'|'Medium'|'Low'} confidence
 * @property {number} line
 * @property {string} snippet
 * @property {string} explanation
 * @property {string} fix
 * @property {string} source
 */

'use strict';

const VALID_SEVERITIES  = new Set(['Critical', 'High', 'Medium', 'Low']);
const VALID_CONFIDENCES = new Set(['High', 'Medium', 'Low']);

class BaseRule {
  /**
   * @param {string} idPrefix  — short uppercase prefix (e.g. 'SQL', 'XSS')
   * @param {string} name      — human-readable rule name
   */
  constructor(idPrefix, name) {
    if (new.target === BaseRule) {
      throw new Error('BaseRule is abstract — extend it, do not instantiate directly.');
    }
    this.idPrefix = idPrefix;
    this.name     = name;
    this._counter = 1;
  }

  /**
   * Run this rule against a parsed context.
   *
   * @param {ParsedContext} _context
   * @returns {Issue[]}
   */
  // eslint-disable-next-line no-unused-vars
  analyze(_context) {
    throw new Error(`${this.constructor.name}.analyze() is not implemented.`);
  }

  /**
   * Reset the per-request ID counter.
   * Called automatically by the rule registry before each analysis run.
   */
  reset() {
    this._counter = 1;
  }

  /**
   * Build a well-formed Issue object.
   *
   * @param {string} type
   * @param {'Critical'|'High'|'Medium'|'Low'} severity
   * @param {number} lineNum             — 1-based line number
   * @param {string} trimmed             — trimmed source line (snippet)
   * @param {string} explanation
   * @param {string} fix
   * @param {'High'|'Medium'|'Low'} [confidence='High']
   * @param {string} [source='rule']
   * @returns {Issue}
   */
  _buildIssue(type, severity, lineNum, trimmed, explanation, fix, confidence = 'High', source = 'rule') {
    const id = `${this.idPrefix}_${String(this._counter++).padStart(3, '0')}`;
    return {
      id,
      type,
      severity:   VALID_SEVERITIES.has(severity)   ? severity   : 'Medium',
      confidence: VALID_CONFIDENCES.has(confidence) ? confidence : 'Medium',
      line:       lineNum,
      snippet:    trimmed.slice(0, 200),
      explanation,
      fix,
      source,
    };
  }

  /**
   * Convenience wrapper for taint-engine-derived issues.
   * Sets source='taint' and defaults confidence to 'Medium'.
   */
  _buildTaintIssue(type, severity, lineNum, trimmed, explanation, fix, confidence = 'Medium') {
    return this._buildIssue(type, severity, lineNum, trimmed, explanation, fix, confidence, 'taint');
  }

  /**
   * Return true if the trimmed line is a comment-only line (should be skipped).
   */
  _isComment(trimmed) {
    return !trimmed || /^\s*(?:\/\/|#|\*|\/\*)/.test(trimmed);
  }
}

module.exports = BaseRule;
