/**
 * tests/rules.test.js
 * Unit tests for individual security rule classes using Node's built-in assert.
 * Run: node tests/rules.test.js
 */

'use strict';

const assert               = require('assert');
const InputParser           = require('../parser');
const SqlInjectionRule      = require('../rules/sql-injection/SqlInjectionRule');
const XssRule               = require('../rules/xss/XssRule');
const VendorSecretsRule     = require('../rules/secrets/VendorSecretsRule');
const SecretsRule           = require('../rules/secrets/SecretsRule');
const EvalRule              = require('../rules/unsafe-patterns/EvalRule');
const CommandInjectionRule  = require('../rules/unsafe-patterns/CommandInjectionRule');
const DeserializationRule   = require('../rules/unsafe-patterns/DeserializationRule');
const CryptoRule            = require('../rules/unsafe-patterns/CryptoRule');
const PathTraversalRule     = require('../rules/unsafe-patterns/PathTraversalRule');
const MiscRule              = require('../rules/unsafe-patterns/MiscRule');
const { runRules }          = require('../rules');

const parser = new InputParser();

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

// ── SQL Injection ────────────────────────────────────────────────────────────
console.log('\n── SqlInjectionRule ───────────────────────────────────────────');
const sqlRule = new SqlInjectionRule();

test('detects JS string concatenation in query', () => {
  const issues = sqlRule.analyze(ctx('const q = "SELECT * FROM users WHERE id = " + userId;'));
  assert.ok(issues.length > 0, 'expected at least one issue');
  assert.strictEqual(issues[0].type, 'SQL Injection');
  assert.strictEqual(issues[0].severity, 'High');
  assert.ok(issues[0].id.startsWith('SQL_'));
});

test('detects Python % formatting in SQL', () => {
  const code = `cursor.execute("SELECT * FROM t WHERE u = '%s'" % val)`;
  sqlRule.reset();
  const issues = sqlRule.analyze(ctx(code, 'python'));
  assert.ok(issues.length > 0);
});

test('detects Java JDBC concatenation', () => {
  const code = `rs = stmt.executeQuery("SELECT * FROM t WHERE id = " + userId);`;
  sqlRule.reset();
  const issues = sqlRule.analyze(ctx(code, 'java'));
  assert.ok(issues.length > 0);
});

test('skips comment lines', () => {
  const code = '// query = "SELECT * FROM t WHERE id = " + id';
  sqlRule.reset();
  assert.strictEqual(sqlRule.analyze(ctx(code)).length, 0);
});

test('skips safe parameterized query', () => {
  const code = 'db.query("SELECT * FROM users WHERE id = $1", [userId]);';
  sqlRule.reset();
  assert.strictEqual(sqlRule.analyze(ctx(code)).length, 0);
});

// ── XSS ─────────────────────────────────────────────────────────────────────
console.log('\n── XssRule ────────────────────────────────────────────────────');
const xssRule = new XssRule();

test('detects innerHTML assignment', () => {
  const issues = xssRule.analyze(ctx('el.innerHTML = userInput;'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Cross-Site Scripting (XSS)');
});

test('detects document.write()', () => {
  xssRule.reset();
  const issues = xssRule.analyze(ctx('document.write(data);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].severity, 'High');
});

test('detects dangerouslySetInnerHTML', () => {
  xssRule.reset();
  const issues = xssRule.analyze(ctx('<div dangerouslySetInnerHTML={{ __html: html }} />'));
  assert.ok(issues.length > 0);
});

test('detects Python mark_safe()', () => {
  xssRule.reset();
  const issues = xssRule.analyze(ctx('return mark_safe(user_data)', 'python'));
  assert.ok(issues.length > 0);
});

// ── Vendor Secrets ───────────────────────────────────────────────────────────
console.log('\n── VendorSecretsRule ──────────────────────────────────────────');
const vendorRule = new VendorSecretsRule();

test('detects AWS Access Key ID', () => {
  const issues = vendorRule.analyze(ctx('const key = "AKIAIOSFODNN7EXAMPLE";'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Hardcoded Secret');
  assert.ok(issues[0].snippet.includes('[REDACTED]'));
});

test('detects GitHub token', () => {
  vendorRule.reset();
  const issues = vendorRule.analyze(ctx('const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";'));
  assert.ok(issues.length > 0);
});

test('skips import statements', () => {
  vendorRule.reset();
  const issues = vendorRule.analyze(ctx('import { AKIA } from "aws-sdk";'));
  assert.strictEqual(issues.length, 0);
});

// ── Secrets Heuristic ────────────────────────────────────────────────────────
console.log('\n── SecretsRule ────────────────────────────────────────────────');
const secretRule = new SecretsRule();

test('detects hardcoded password assignment', () => {
  const issues = secretRule.analyze(ctx('const password = "hunter2securepassword";'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Hardcoded Credential');
});

test('skips env var reference', () => {
  secretRule.reset();
  const issues = secretRule.analyze(ctx('const password = process.env.PASSWORD;'));
  assert.strictEqual(issues.length, 0);
});

test('skips placeholder values', () => {
  secretRule.reset();
  const issues = secretRule.analyze(ctx('const password = "your_password_here";'));
  assert.strictEqual(issues.length, 0);
});

// ── Eval ─────────────────────────────────────────────────────────────────────
console.log('\n── EvalRule ───────────────────────────────────────────────────');
const evalRule = new EvalRule();

test('detects eval()', () => {
  const issues = evalRule.analyze(ctx('const result = eval(userInput);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Dangerous eval()');
});

test('detects new Function()', () => {
  evalRule.reset();
  const issues = evalRule.analyze(ctx('const fn = new Function("return " + code);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Unsafe Function Constructor');
});

// ── Command Injection ─────────────────────────────────────────────────────────
console.log('\n── CommandInjectionRule ───────────────────────────────────────');
const cmdRule = new CommandInjectionRule();

test('detects Python os.system()', () => {
  const issues = cmdRule.analyze(ctx('os.system("ls " + path)', 'python'));
  assert.ok(issues.length > 0);
  assert.ok(issues[0].type.includes('Command Injection'));
});

test('detects subprocess with shell=True', () => {
  cmdRule.reset();
  const issues = cmdRule.analyze(
    ctx('subprocess.run(cmd, shell=True)', 'python')
  );
  assert.ok(issues.length > 0);
});

test('detects Java Runtime.exec()', () => {
  cmdRule.reset();
  const issues = cmdRule.analyze(
    ctx('Runtime.getRuntime().exec("ls " + dir)', 'java')
  );
  assert.ok(issues.length > 0);
});

// ── Deserialization ───────────────────────────────────────────────────────────
console.log('\n── DeserializationRule ────────────────────────────────────────');
const deserRule = new DeserializationRule();

test('detects pickle.loads()', () => {
  const issues = deserRule.analyze(ctx('data = pickle.loads(raw)', 'python'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Insecure Deserialization (pickle)');
});

test('detects yaml.load() without SafeLoader', () => {
  deserRule.reset();
  const issues = deserRule.analyze(ctx('config = yaml.load(f)', 'python'));
  assert.ok(issues.length > 0);
});

// ── Crypto ────────────────────────────────────────────────────────────────────
console.log('\n── CryptoRule ─────────────────────────────────────────────────');
const cryptoRule = new CryptoRule();

test('detects rejectUnauthorized: false', () => {
  const issues = cryptoRule.analyze(ctx('const opts = { rejectUnauthorized: false };'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'TLS Verification Disabled');
});

test('detects MD5 usage', () => {
  cryptoRule.reset();
  const issues = cryptoRule.analyze(ctx('const hash = md5(password);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Weak Cryptographic Hash');
});

test('detects Math.random()', () => {
  cryptoRule.reset();
  const issues = cryptoRule.analyze(ctx('const token = Math.random().toString(36);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Insecure Randomness');
});

// ── Path Traversal ────────────────────────────────────────────────────────────
console.log('\n── PathTraversalRule ──────────────────────────────────────────');
const pathRule = new PathTraversalRule();

test('detects readFile with request param', () => {
  const issues = pathRule.analyze(ctx('fs.readFile(req.params.file, cb);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Path Traversal');
});

// ── Misc ──────────────────────────────────────────────────────────────────────
console.log('\n── MiscRule ───────────────────────────────────────────────────');
const miscRule = new MiscRule();

test('detects prototype pollution via __proto__', () => {
  const issues = miscRule.analyze(ctx('obj.__proto__[key] = value;'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Prototype Pollution');
});

test('detects sensitive data logging', () => {
  miscRule.reset();
  const issues = miscRule.analyze(ctx('console.log("token:", authToken);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Sensitive Data Logged');
});

test('detects open redirect', () => {
  miscRule.reset();
  const issues = miscRule.analyze(ctx('res.redirect(req.query.url);'));
  assert.ok(issues.length > 0);
  assert.strictEqual(issues[0].type, 'Open Redirect');
});

test('detects Java XXE risk', () => {
  miscRule.reset();
  const issues = miscRule.analyze(
    ctx('DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();', 'java')
  );
  assert.ok(issues.length > 0);
  assert.ok(issues[0].type.includes('XXE'));
});

// ── Full Pipeline via runRules ────────────────────────────────────────────────
console.log('\n── Full Pipeline (runRules) ───────────────────────────────────');

test('JS snippet triggers SQL + XSS + Secrets issues', () => {
  const code = [
    'const pw = "hunter2securepassword";',
    'const q  = "SELECT * FROM users WHERE id = " + userId;',
    'document.getElementById("out").innerHTML = userInput;',
  ].join('\n');
  const issues = runRules(parser.parse(code, 'javascript'));
  const types = issues.map(i => i.type);
  assert.ok(types.some(t => t === 'SQL Injection'), 'expected SQL Injection');
  assert.ok(types.some(t => t === 'Cross-Site Scripting (XSS)'), 'expected XSS');
  assert.ok(types.some(t => t === 'Hardcoded Credential'), 'expected Credential');
});

test('Python snippet triggers Command + Deserialization + SQL issues', () => {
  const code = [
    'import pickle, os, sqlite3',
    'data = pickle.loads(untrusted)',
    'os.system("rm -rf " + path)',
    'cursor.execute("SELECT * FROM t WHERE x = \'%s\'" % val)',
  ].join('\n');
  const issues = runRules(parser.parse(code, 'python'));
  const types = issues.map(i => i.type);
  assert.ok(types.some(t => t.includes('Deserialization')), 'expected Deserialization');
  assert.ok(types.some(t => t.includes('Command')), 'expected Command Injection');
  assert.ok(types.some(t => t === 'SQL Injection'), 'expected SQL Injection');
});

test('Java snippet triggers SQL + Command + XXE issues', () => {
  const code = [
    'String q = "SELECT * FROM users WHERE id = " + userId;',
    'Runtime.getRuntime().exec("ls " + dir);',
    'DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();',
  ].join('\n');
  const issues = runRules(parser.parse(code, 'java'));
  const types = issues.map(i => i.type);
  assert.ok(types.some(t => t === 'SQL Injection'), 'expected SQL Injection');
  assert.ok(types.some(t => t.includes('Command Injection') || t.includes('Command')), 'expected Command Injection');
  assert.ok(types.some(t => t.includes('XXE')), 'expected XXE');
});

// ── Summary ─────────────────────────────────────────────────────────────────
console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
console.log('✓ All rules tests passed\n');
