/**
 * taint/TaintEngine.js
 *
 * Heuristic taint analysis engine.
 *
 * Algorithm (line-by-line, no AST required):
 *
 *   1. extractSources(lines, language)
 *      → Scan for source patterns (req.body, input(), getParameter(), etc.)
 *      → Return Map<varName, {line, label}> of initially tainted variables
 *
 *   2. propagate(lines, taintedVars)
 *      → Scan for assignments: `x = taintedVar` or `x = taintedVar + ...`
 *      → Add newly tainted variables to the map (one-level indirect propagation)
 *      → Repeat until no new variables are added (fixed-point)
 *
 *   3. checkSinks(lines, taintedVars, language)
 *      → For each line containing a sink pattern, check if any tainted
 *        variable name appears on the same line
 *      → If yes → emit an Issue with confidence based on propagation depth
 *
 * Usage:
 *   const TaintEngine = require('../taint/TaintEngine');
 *   const issues = new TaintEngine().analyze(context);
 */

'use strict';

const { SOURCES } = require('./sources');
const { SINKS   } = require('./sinks');

/** Max propagation iterations to prevent infinite loops. */
const MAX_PROPAGATION_ROUNDS = 8;

class TaintEngine {
  /**
   * Full taint analysis pipeline.
   *
   * @param {import('../rules/base/BaseRule').ParsedContext} context
   * @returns {object[]} Issue objects (no id prefix — uses TAINT_ prefix)
   */
  analyze(context) {
    const { lines, language } = context;

    // Step 1: identify source variables
    const taintedVars = this._extractSources(lines, language);
    if (taintedVars.size === 0) return []; // no tainted input → nothing to track

    // Step 2: propagate taint through assignments
    this._propagate(lines, taintedVars);

    // Step 3: find sinks where tainted variables appear
    return this._checkSinks(lines, taintedVars, language);
  }

  // ── Step 1: Source extraction ────────────────────────────────────────────────

  /**
   * @param {string[]} lines
   * @param {string}   language
   * @returns {Map<string, {lineNum: number, label: string, depth: number}>}
   */
  _extractSources(lines, language) {
    const taintedVars = new Map();
    const patterns    = SOURCES[language] || [];

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed || /^\s*(?:\/\/|#|\*)/.test(trimmed)) return;

      for (const { pattern, label } of patterns) {
        const cloned = new RegExp(pattern.source, pattern.flags);
        const m = cloned.exec(line);
        if (m) {
          // Named group 'varName' captures the newly-tainted variable
          const varName = m.groups && m.groups.varName;
          if (varName && !taintedVars.has(varName)) {
            taintedVars.set(varName, { lineNum: idx + 1, label, depth: 0 });
          }
          // Destructuring patterns don't have a single varName — extract from braces
          if (!varName) {
            const destructureMatch = line.match(/\{([^}]+)\}/);
            if (destructureMatch) {
              destructureMatch[1].split(',').map(s => s.trim().split(':')[0].trim()).forEach(v => {
                if (v && /^\w+$/.test(v) && !taintedVars.has(v)) {
                  taintedVars.set(v, { lineNum: idx + 1, label, depth: 0 });
                }
              });
            }
          }
        }
      }
    });

    return taintedVars;
  }

  // ── Step 2: Propagation ──────────────────────────────────────────────────────

  /**
   * Propagate taint through simple assignment chains.
   * Modifies taintedVars in place.
   *
   * @param {string[]} lines
   * @param {Map}      taintedVars
   */
  _propagate(lines, taintedVars) {
    for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
      let addedThisRound = 0;

      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed || /^\s*(?:\/\/|#|\*)/.test(trimmed)) return;

        // Detect: newVar = <something involving a taintedVar>
        // Patterns: simple assignment, augmented assignment, destructuring
        const assignMatch = line.match(
          /(?:(?:const|let|var|String|int|long)\s+)?(\w+)\s*=\s*(.+)/
        );
        if (!assignMatch) return;

        const [, lhs, rhs] = assignMatch;
        if (!lhs || taintedVars.has(lhs)) return; // already tainted or not an assignment

        // Check if any tainted variable appears in the RHS
        for (const [tVar, info] of taintedVars) {
          // Look for the tainted var as a word boundary match (not as substring of other words)
          const varRe = new RegExp(`\\b${tVar}\\b`);
          if (varRe.test(rhs)) {
            taintedVars.set(lhs, { lineNum: idx + 1, label: `propagated from ${info.label}`, depth: info.depth + 1 });
            addedThisRound++;
            break;
          }
        }
      });

      if (addedThisRound === 0) break; // fixed point reached
    }
  }

  // ── Step 3: Sink checking ────────────────────────────────────────────────────

  /**
   * @param {string[]} lines
   * @param {Map}      taintedVars
   * @param {string}   language
   * @returns {object[]}
   */
  _checkSinks(lines, taintedVars, language) {
    const sinkPatterns = SINKS[language] || [];
    const issues       = [];
    const seen         = new Set(); // deduplicate by (line, type)
    let counter        = 1;

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed || /^\s*(?:\/\/|#|\*)/.test(trimmed)) return;

      for (const { pattern, type, severity, explanation, fix } of sinkPatterns) {
        const sinkClone = new RegExp(pattern.source, pattern.flags);
        if (!sinkClone.test(line)) continue;

        // Check if a tainted variable appears on the same line
        let matchedVar  = null;
        let matchedInfo = null;

        for (const [varName, info] of taintedVars) {
          const varRe = new RegExp(`\\b${varName}\\b`);
          if (varRe.test(line)) {
            matchedVar  = varName;
            matchedInfo = info;
            break;
          }
        }

        if (!matchedVar) continue; // sink found but no tainted var on this line

        const key = `${idx + 1}::${type}`;
        if (seen.has(key)) continue;
        seen.add(key);

        // Confidence: depth 0 = High (direct source→sink), depth 1 = Medium, deeper = Low
        const depth      = matchedInfo.depth || 0;
        const confidence = depth === 0 ? 'High' : depth === 1 ? 'Medium' : 'Low';

        const enhancedExplanation =
          `${explanation}\n[Taint] Variable "${matchedVar}" originates from: ${matchedInfo.label} (line ${matchedInfo.lineNum}).`;

        issues.push({
          id:          `TAINT_${String(counter++).padStart(3, '0')}`,
          type,
          severity,
          confidence,
          line:        idx + 1,
          snippet:     trimmed.slice(0, 200),
          explanation: enhancedExplanation,
          fix,
          source:      'taint',
        });
      }
    });

    return issues;
  }
}

module.exports = TaintEngine;
