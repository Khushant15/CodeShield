/**
 * tests/reporter.test.js
 * Unit tests for the Reporter module using Node's built-in assert.
 * Run: node tests/reporter.test.js
 */

'use strict';

const assert   = require('assert');
const Reporter = require('../reporter');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

function makeIssue(line, type, severity = 'High') {
  return { id: `T_001`, type, severity, line, snippet: 'code', explanation: 'e', fix: 'f' };
}

console.log('\n── Reporter Tests ─────────────────────────────────────────────');

const reporter = new Reporter();

test('returns empty array for empty input', () => {
  assert.deepStrictEqual(reporter.report([]), []);
});

test('returns empty array for non-array input', () => {
  assert.deepStrictEqual(reporter.report(null), []);
});

test('sorts issues by line ascending', () => {
  const issues = [
    makeIssue(5, 'XSS'),
    makeIssue(2, 'SQL Injection'),
    makeIssue(10, 'Hardcoded Secret'),
  ];
  const result = reporter.report(issues);
  assert.strictEqual(result[0].line, 2);
  assert.strictEqual(result[1].line, 5);
  assert.strictEqual(result[2].line, 10);
});

test('deduplicates issues with same line + type', () => {
  const issues = [
    makeIssue(3, 'eval()'),
    makeIssue(3, 'eval()'),   // duplicate
    makeIssue(3, 'XSS'),      // different type — kept
  ];
  const result = reporter.report(issues);
  assert.strictEqual(result.length, 2);
});

test('keeps issues with same type on different lines', () => {
  const issues = [
    makeIssue(1, 'SQL Injection'),
    makeIssue(5, 'SQL Injection'),
  ];
  const result = reporter.report(issues);
  assert.strictEqual(result.length, 2);
});

test('preserves all issue fields', () => {
  const issue = {
    id: 'SQL_001', type: 'SQL Injection', severity: 'High',
    line: 7, snippet: 'query += id', explanation: 'bad', fix: 'use params',
  };
  const result = reporter.report([issue]);
  assert.deepStrictEqual(result[0], issue);
});

// ── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
console.log('✓ All reporter tests passed\n');
