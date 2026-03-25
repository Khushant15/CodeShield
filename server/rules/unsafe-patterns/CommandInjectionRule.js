/**
 * rules/unsafe-patterns/CommandInjectionRule.js
 *
 * Detects OS command injection vectors across JavaScript, Python, and Java.
 */

'use strict';

const BaseRule = require('../base/BaseRule');

const PATTERNS = [
  {
    regex: /\bexec\s*\(\s*(?:[^)]*\+|`[^`]*\$\{|req\.|request\.|params\.|query\.|body\.|\w+[Ii]nput|\w+[Cc]md|\w+[Cc]ommand)/,
    type: 'Command Injection',
    severity: 'High',
    explanation:
      'exec() with concatenated or user-supplied input allows OS command injection — ' +
      'an attacker can run any command on your server.',
    fix: 'Use execFile() / spawn() with an explicit argument array. Never pass shell strings from user input.',
  },
  {
    regex: /child_process.*exec\b/,
    type: 'Command Injection Risk',
    severity: 'High',
    explanation:
      'child_process.exec() runs commands through the shell. ' +
      'If any argument contains user data, it is command injection.',
    fix: 'Prefer child_process.execFile(cmd, [args]) — it does not invoke a shell and is safe with user arguments.',
  },
  {
    regex: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/,
    type: 'Command Injection (Python shell=True)',
    severity: 'High',
    explanation:
      'subprocess with shell=True passes the command through /bin/sh — ' +
      'user input in the command string enables injection.',
    fix: 'Remove shell=True and pass arguments as a list:\n  subprocess.run(["ls", filename], shell=False)',
  },
  {
    regex: /\bos\.system\s*\(/,
    type: 'Command Injection (os.system)',
    severity: 'High',
    explanation:
      'os.system() executes a shell command. Any user-controlled content in the argument is a command injection vulnerability.',
    fix: 'Replace with subprocess.run([cmd, arg]) without shell=True.',
  },
  {
    regex: /Runtime\.getRuntime\(\)\.exec\s*\(/,
    type: 'Command Injection (Java Runtime.exec)',
    severity: 'High',
    explanation: 'Runtime.exec() concatenating user input allows OS command injection.',
    fix: 'Pass a String[] to ProcessBuilder — never concatenate user input into a command string.',
  },
];

class CommandInjectionRule extends BaseRule {
  constructor() {
    super('UNSAFE_CMD', 'Command Injection');
  }

  /**
   * @param {import('../base/BaseRule').ParsedContext} context
   * @returns {import('../base/BaseRule').Issue[]}
   */
  analyze(context) {
    const { lines } = context;
    const issues = [];

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (this._isComment(trimmed)) return;

      for (const { regex, type, severity, explanation, fix } of PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          issues.push(this._buildIssue(type, severity, idx + 1, trimmed, explanation, fix));
          break;
        }
      }
    });

    return issues;
  }
}

module.exports = CommandInjectionRule;
