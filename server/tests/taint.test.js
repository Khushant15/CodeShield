/**
 * tests/taint.test.js
 * Unit tests for the TaintEngine using Node's built-in assert.
 * Run: node tests/taint.test.js
 */

'use strict';

const assert       = require('assert');
const InputParser  = require('../parser');
const TaintEngine  = require('../taint/TaintEngine');

const parser = new InputParser();
const taint  = new TaintEngine();

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

function ctx(code, lang = 'javascript') {
  return parser.parse(code, lang);
}

// ── Source extraction ────────────────────────────────────────────────────────
console.log('\n── TaintEngine: Source Extraction ────────────────────────────');

test('JS: detects req.body taint source', () => {
  const code = 'const userId = req.body.id;';
  const issues = taint.analyze(ctx(code));
  // Even with no sink, extractSources should populate; no issue yet
  // Test by adding a sink on the next line
  const code2 = [
    'const userId = req.body.id;',
    'db.query("SELECT * FROM users WHERE id = " + userId);',
  ].join('\n');
  const issues2 = taint.analyze(ctx(code2));
  assert.ok(issues2.length > 0, 'expected taint issue from req.body → SQL query');
  assert.ok(issues2[0].type.includes('SQL'), `expected SQL type, got: ${issues2[0].type}`);
  assert.strictEqual(issues2[0].source, 'taint');
});

test('JS: detects req.query taint flowing to exec', () => {
  const code = [
    'const cmd = req.query.command;',
    'exec(cmd);',
  ].join('\n');
  const issues = taint.analyze(ctx(code));
  assert.ok(issues.length > 0, 'expected command injection taint issue');
  assert.ok(issues[0].type.includes('Command'), `type: ${issues[0].type}`);
  assert.strictEqual(issues[0].confidence, 'High', 'direct source→sink should be High confidence');
});

test('JS: detects req.params taint flowing to readFile', () => {
  const code = [
    'const filename = req.params.file;',
    'fs.readFile(filename, "utf8", cb);',
  ].join('\n');
  const issues = taint.analyze(ctx(code));
  assert.ok(issues.length > 0, 'expected path traversal taint issue');
  assert.ok(issues[0].type.includes('Path Traversal'), `type: ${issues[0].type}`);
});

test('JS: propagation — taint through intermediate variable', () => {
  const code = [
    'const raw = req.body.name;',
    'const safe = raw;',            // propagated
    'res.send(safe);',              // sink
  ].join('\n');
  const issues = taint.analyze(ctx(code));
  assert.ok(issues.length > 0, 'expected reflected data issue after propagation');
  // Propagated through one variable — confidence should be Medium or lower
  assert.ok(['Medium', 'Low'].includes(issues[0].confidence),
    `expected Medium/Low confidence for propagated taint, got: ${issues[0].confidence}`);
});

test('JS: no issue when no taint source present', () => {
  const code = [
    'const safeId = 42;',
    'db.query("SELECT * FROM users WHERE id = " + safeId);',
  ].join('\n');
  const issues = taint.analyze(ctx(code));
  assert.strictEqual(issues.length, 0, 'no taint source → no taint issue');
});

// ── Python taint ─────────────────────────────────────────────────────────────
console.log('\n── TaintEngine: Python ────────────────────────────────────────');

test('Python: request.args flowing into execute()', () => {
  const code = [
    'user_id = request.args.get("id")',
    'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
  ].join('\n');
  const issues = taint.analyze(ctx(code, 'python'));
  assert.ok(issues.length > 0, 'expected SQL taint issue');
  assert.ok(issues[0].type.includes('SQL'), `type: ${issues[0].type}`);
});

test('Python: input() flowing into os.system()', () => {
  const code = [
    'cmd = input("Enter command: ")',
    'os.system(cmd)',
  ].join('\n');
  const issues = taint.analyze(ctx(code, 'python'));
  assert.ok(issues.length > 0, 'expected command injection taint issue');
  assert.ok(issues[0].type.includes('Command'), `type: ${issues[0].type}`);
});

test('Python: request.form flowing into open()', () => {
  const code = [
    'path = request.form["filename"]',
    'with open(path) as f:',
    '    data = f.read()',
  ].join('\n');
  const issues = taint.analyze(ctx(code, 'python'));
  assert.ok(issues.length > 0, 'expected path traversal taint issue');
  assert.ok(issues[0].type.includes('Path Traversal'), `type: ${issues[0].type}`);
});

test('Python: render_template_string with tainted input is Critical', () => {
  const code = [
    'template = request.args.get("tmpl")',
    'return render_template_string(template)',
  ].join('\n');
  const issues = taint.analyze(ctx(code, 'python'));
  assert.ok(issues.length > 0, 'expected SSTI issue');
  assert.ok(issues[0].type.includes('Template'), `type: ${issues[0].type}`);
  assert.strictEqual(issues[0].severity, 'Critical');
});

// ── Java taint ────────────────────────────────────────────────────────────────
console.log('\n── TaintEngine: Java ──────────────────────────────────────────');

test('Java: getParameter flowing into executeQuery', () => {
  const code = [
    'String userId = request.getParameter("id");',
    'ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);',
  ].join('\n');
  const issues = taint.analyze(ctx(code, 'java'));
  assert.ok(issues.length > 0, 'expected SQL taint issue');
  assert.ok(issues[0].type.includes('SQL'), `type: ${issues[0].type}`);
});

test('Java: getParameter flowing into Runtime.exec', () => {
  const code = [
    'String cmd = request.getParameter("cmd");',
    'Runtime.getRuntime().exec(cmd);',
  ].join('\n');
  const issues = taint.analyze(ctx(code, 'java'));
  assert.ok(issues.length > 0, 'expected command injection taint issue');
  assert.strictEqual(issues[0].severity, 'Critical');
});

test('Java: taint issue has correct explanation with origin info', () => {
  const code = [
    'String input = request.getParameter("q");',
    'ResultSet rs = stmt.executeQuery("SELECT * FROM t WHERE id = " + input);',
  ].join('\n');
  const issues = taint.analyze(ctx(code, 'java'));
  assert.ok(issues.length > 0);
  assert.ok(issues[0].explanation.includes('[Taint]'), 'explanation should include [Taint] origin info');
  assert.ok(issues[0].explanation.includes('"input"'), 'should name the tainted variable');
});

// ── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
console.log('✓ All taint tests passed\n');
