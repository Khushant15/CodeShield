/**
 * taint/sinks.js
 *
 * Defines sink patterns per language for taint analysis.
 * A sink is a dangerous operation where tainted (user-controlled) data
 * reaching it indicates a vulnerability.
 *
 * Each sink specifies:
 *   - pattern: RegExp tested against the full source line
 *   - type:    issue type name
 *   - severity: 'Critical' | 'High' | 'Medium'
 *   - explanation + fix: filled in when a tainted var reaches this sink
 */

'use strict';

/**
 * @type {Record<string, {pattern: RegExp, type: string, severity: string, explanation: string, fix: string}[]>}
 */
const SINKS = {
  javascript: [
    // SQL sinks
    {
      pattern: /\.(?:query|execute|run)\s*\(/,
      type: 'SQL Injection (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input flows directly into a SQL query execution call without sanitization.',
      fix: 'Use parameterized queries:\n  db.query("SELECT * FROM t WHERE id = $1", [userInput])',
    },
    {
      pattern: /\.(?:raw|from)\s*\(\s*[`'"]/,
      type: 'SQL Injection via ORM raw() (Taint)',
      severity: 'High',
      explanation: 'Tainted data passed to an ORM raw query bypasses parameterization protection.',
      fix: 'Use tagged templates or parameterized ORM methods instead of raw().',
    },
    // File sinks
    {
      pattern: /(?:readFile|writeFile|createReadStream|createWriteStream|readFileSync|writeFileSync)\s*\(/,
      type: 'Path Traversal (Taint)',
      severity: 'High',
      explanation: 'Tainted user input used as a file path — path traversal (../../) attack possible.',
      fix: 'Resolve and validate the path:\n  const safe = path.resolve(BASE, input);\n  if (!safe.startsWith(BASE)) throw new Error("Traversal blocked");',
    },
    // Shell sinks
    {
      pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(/,
      type: 'Command Injection (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input passed to a shell execution function enables OS command injection.',
      fix: 'Use execFile() with a fixed command and array args:\n  execFile("cmd", [safeArg])',
    },
    // Response sinks
    {
      pattern: /res\.(?:send|json|write|end)\s*\(/,
      type: 'Reflected Data in Response (Taint)',
      severity: 'Medium',
      explanation: 'Tainted user input is reflected in the HTTP response without encoding — reflected XSS or information leakage risk.',
      fix: 'Sanitize output: encode HTML entities or use a template engine with auto-escaping.',
    },
    // eval / code execution
    {
      pattern: /\beval\s*\(/,
      type: 'Code Injection via eval (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input reaches eval() — direct code injection vulnerability.',
      fix: 'Never pass user input to eval(). Use JSON.parse() for data or a lookup map for dispatch.',
    },
  ],

  python: [
    // SQL sinks
    {
      pattern: /\.execute\s*\(/,
      type: 'SQL Injection (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input flows into a SQL execute() call — SQL injection risk.',
      fix: 'Use parameterized queries:\n  cursor.execute("SELECT * FROM t WHERE id = %s", (user_id,))',
    },
    // Shell sinks
    {
      pattern: /(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(/,
      type: 'Command Injection (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input reaches an OS command execution call — command injection risk.',
      fix: 'Pass arguments as a list without shell=True:\n  subprocess.run(["cmd", safe_arg], shell=False)',
    },
    // File sinks
    {
      pattern: /\bopen\s*\(/,
      type: 'Path Traversal (Taint)',
      severity: 'High',
      explanation: 'Tainted file path passed to open() — an attacker can read or overwrite arbitrary files.',
      fix: 'Validate the path is within an allowed directory:\n  safe = os.path.realpath(path)\n  assert safe.startswith(ALLOWED_BASE)',
    },
    // Response sinks
    {
      pattern: /(?:print|return\s+(?:jsonify|render_template|make_response))\s*\(/,
      type: 'Reflected Data in Response (Taint)',
      severity: 'Medium',
      explanation: 'Tainted user input is output in the response without encoding — potential reflected XSS.',
      fix: 'Use Jinja2 auto-escaping (default in Flask) and avoid|safe filter with unvalidated input.',
    },
    // Template injection
    {
      pattern: /render_template_string\s*\(/,
      type: 'Server-Side Template Injection (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input passed to render_template_string() allows SSTI — arbitrary code execution.',
      fix: 'Never pass user input to render_template_string(). Use render_template() with static filenames.',
    },
  ],

  java: [
    // SQL sinks
    {
      pattern: /\.(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(/,
      type: 'SQL Injection (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input flows into a JDBC execute call — SQL injection vulnerability.',
      fix: 'Use PreparedStatement:\n  PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\n  ps.setString(1, userId);',
    },
    // Shell sinks
    {
      pattern: /Runtime\.getRuntime\(\)\.exec\s*\(/,
      type: 'Command Injection (Taint)',
      severity: 'Critical',
      explanation: 'Tainted user input reaches Runtime.exec() — OS command injection risk.',
      fix: 'Use ProcessBuilder with a String[] — never concatenate user input.',
    },
    // Response sinks (Servlet)
    {
      pattern: /(?:getWriter|PrintWriter)\s*\(\s*\)/,
      type: 'Reflected Data in Response (Taint)',
      severity: 'High',
      explanation: 'Tainted user input written to the HTTP response via PrintWriter — reflected XSS.',
      fix: 'HTML-encode output:\n  out.print(StringEscapeUtils.escapeHtml4(userInput));',
    },
    // File sinks
    {
      pattern: /new\s+File(?:Reader|InputStream|Writer|OutputStream)\s*\(/,
      type: 'Path Traversal (Taint)',
      severity: 'High',
      explanation: 'Tainted user input used as a file system path may allow path traversal.',
      fix: 'Canonicalize and validate:\n  File f = new File(BASE, input).getCanonicalFile();\n  if (!f.toPath().startsWith(BASE)) throw new SecurityException();',
    },
  ],
};

module.exports = { SINKS };
