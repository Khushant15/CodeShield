/**
 * parser/index.js — Input Parser
 *
 * Normalizes raw code + language into a reusable ParsedContext object.
 * Splits lines exactly once so every downstream rule reuses the same array.
 *
 * Usage:
 *   const InputParser = require('../parser');
 *   const ctx = new InputParser().parse(code, language);
 *   // ctx → { code, language, lines, lineCount }
 */

'use strict';

const SUPPORTED_LANGUAGES = new Set(['javascript', 'python', 'java']);

/**
 * @typedef {Object} ParsedContext
 * @property {string}   code       — original source string (trimmed)
 * @property {string}   language   — normalised lowercase language identifier
 * @property {string[]} lines      — source split on newlines (1-indexed: lines[0] = line 1)
 * @property {number}   lineCount  — total number of lines
 */

class InputParser {
  /**
   * Parse and validate raw input.
   *
   * @param {string} code     — raw source code submitted by the user
   * @param {string} language — target language ('javascript' | 'python' | 'java')
   * @returns {ParsedContext}
   * @throws {Error} if code or language is invalid
   */
  /**
   * @param {string} code       — raw source code
   * @param {string} language   — 'javascript' | 'python' | 'java'
   * @param {string} [filename] — optional file name label for output
   */
  parse(code, language, filename = '<input>') {
    // ── Validate code ──────────────────────────────────────────────────────────
    if (typeof code !== 'string' || code.trim().length === 0) {
      throw new Error('InputParser: code must be a non-empty string.');
    }

    // ── Validate & normalise language ──────────────────────────────────────────
    const lang = (typeof language === 'string' ? language : '').trim().toLowerCase();
    if (!SUPPORTED_LANGUAGES.has(lang)) {
      throw new Error(
        `InputParser: unsupported language "${language}". ` +
        `Supported: ${[...SUPPORTED_LANGUAGES].join(', ')}.`
      );
    }

    // ── Build context ──────────────────────────────────────────────────────────
    const lines = code.split('\n');

    return Object.freeze({
      code,
      language: lang,
      filename: typeof filename === 'string' ? filename : '<input>',
      lines,
      lineCount: lines.length,
    });
  }
}

module.exports = InputParser;
