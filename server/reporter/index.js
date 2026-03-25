/**
 * reporter/index.js — Reporter
 *
 * Accepts the raw flat list of issues from all rules and:
 *   1. Deduplicates by (line, type) key — keeps the first occurrence
 *   2. Sorts ascending by line number
 *
 * The class is designed to be extended: override `format()` to emit
 * JSON, Markdown, SARIF, JUnit XML, etc.
 *
 * Usage:
 *   const Reporter = require('../reporter');
 *   const issues   = new Reporter().report(rawIssues);
 */

'use strict';

class Reporter {
  /**
   * Process raw issues from the rule engine.
   *
   * @param {object[]} rawIssues — unsorted, potentially duplicated issues
   * @returns {object[]}         — deduplicated, sorted issues
   */
  report(rawIssues) {
    if (!Array.isArray(rawIssues)) return [];

    const deduped = this._deduplicate(rawIssues);
    const sorted  = this._sort(deduped);
    return this.format(sorted);
  }

  /**
   * Deduplicate: same (line, type) pair → keep only the first occurrence.
   *
   * @param {object[]} issues
   * @returns {object[]}
   */
  _deduplicate(issues) {
    const seen = new Set();
    return issues.filter((issue) => {
      const key = `${issue.line}::${issue.type}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Sort: severity descending (Critical→High→Medium→Low), then line ascending.
   *
   * @param {object[]} issues
   * @returns {object[]}
   */
  _sort(issues) {
    const SEV = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    return [...issues].sort((a, b) => {
      const sevDiff = (SEV[a.severity] ?? 4) - (SEV[b.severity] ?? 4);
      return sevDiff !== 0 ? sevDiff : a.line - b.line;
    });
  }

  /**
   * Format hook — override to emit alternative output formats.
   * Default: returns the array as-is.
   *
   * @param {object[]} issues
   * @returns {object[]}
   */
  format(issues) {
    return issues;
  }
}

module.exports = Reporter;
