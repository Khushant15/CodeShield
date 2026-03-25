/**
 * tests/parser.test.js
 * Unit tests for the InputParser module using Node's built-in assert.
 * Run: node tests/parser.test.js
 */

'use strict';

const assert      = require('assert');
const InputParser = require('../parser');

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

console.log('\n── InputParser Tests ──────────────────────────────────────────');

const parser = new InputParser();

test('parses valid JavaScript code', () => {
  const ctx = parser.parse('const x = 1;', 'javascript');
  assert.strictEqual(ctx.language, 'javascript');
  assert.strictEqual(ctx.lineCount, 1);
  assert.deepStrictEqual(ctx.lines, ['const x = 1;']);
  assert.strictEqual(ctx.code, 'const x = 1;');
});

test('normalises language to lowercase', () => {
  const ctx = parser.parse('print("hi")', 'Python');
  assert.strictEqual(ctx.language, 'python');
});

test('accepts java language', () => {
  const ctx = parser.parse('System.out.println("hello");', 'java');
  assert.strictEqual(ctx.language, 'java');
});

test('splits multi-line code correctly', () => {
  const code = 'line1\nline2\nline3';
  const ctx  = parser.parse(code, 'javascript');
  assert.strictEqual(ctx.lineCount, 3);
  assert.strictEqual(ctx.lines[1], 'line2');
});

test('context object is frozen', () => {
  const ctx = parser.parse('let a = 1;', 'javascript');
  assert.ok(Object.isFrozen(ctx), 'context should be frozen');
});

test('throws on empty code string', () => {
  assert.throws(
    () => parser.parse('   ', 'javascript'),
    /non-empty string/
  );
});

test('throws on non-string code', () => {
  assert.throws(
    () => parser.parse(null, 'javascript'),
    /non-empty string/
  );
});

test('throws on unsupported language', () => {
  assert.throws(
    () => parser.parse('code', 'ruby'),
    /unsupported language/
  );
});

test('throws on missing language', () => {
  assert.throws(
    () => parser.parse('code', ''),
    /unsupported language/
  );
});

// ── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
console.log('✓ All parser tests passed\n');
