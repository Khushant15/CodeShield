/**
 * utils/samples.js
 * Pre-loaded vulnerable and safe code samples for testing.
 */
export const SAMPLES = {
  javascript: {
    vulnerable: `// ⚠️  VULNERABLE JavaScript — DO NOT USE IN PRODUCTION
const express = require('express');
const mysql   = require('mysql');
const app     = express();

// Hardcoded credentials — NEVER do this
const DB_PASS = "super_secret_password_123";
const API_KEY = "sk-live-abc123XYZ789defGHI456jkl";
const JWT_SECRET = "my_jwt_secret";

const db = mysql.createConnection({
  host: 'localhost', user: 'root',
  password: DB_PASS, database: 'users'
});

app.get('/user', (req, res) => {
  const userId = req.query.id;

  // SQL Injection: raw string concat
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    if (err) throw err;

    // XSS: directly setting innerHTML with user data
    const html = "<div>" + results[0]?.name + "</div>";
    document.getElementById('output').innerHTML = html;

    res.json(results);
  });
});

app.post('/run', (req, res) => {
  const code = req.body.script;
  // eval with user input — Remote Code Execution
  const result = eval(code);
  res.json({ result });
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // Path traversal vulnerability
  const content = require('fs').readFileSync('../' + filename, 'utf8');
  res.send(content);
});

// Insecure random for token generation
function generateToken() {
  return Math.random().toString(36).substr(2);
}

// setTimeout with string argument (hidden eval)
setTimeout("console.log('hello')", 1000);

console.log("API Key loaded:", API_KEY);
`,
    safe: `// ✅ SECURE JavaScript — production-ready patterns
const express    = require('express');
const mysql      = require('mysql2/promise');
const crypto     = require('crypto');
const path       = require('path');
const DOMPurify  = require('dompurify');
const { JSDOM }  = require('jsdom');
require('dotenv').config();

const app = express();

// ✅ All secrets from environment variables
const db = mysql.createPool({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

app.get('/user', async (req, res) => {
  const userId = req.query.id;

  // ✅ Parameterized query — no SQL injection possible
  const [results] = await db.query(
    'SELECT id, name, email FROM users WHERE id = ?',
    [userId]
  );

  // ✅ Sanitize before rendering
  const window = new JSDOM('').window;
  const purify = DOMPurify(window);
  const safeName = purify.sanitize(results[0]?.name || '');
  document.getElementById('output').textContent = safeName; // textContent, not innerHTML

  res.json(results);
});

// ✅ Cryptographically secure token generation
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ✅ setTimeout with function reference
setTimeout(() => console.log('hello'), 1000);

// ✅ Path traversal prevention
app.get('/file', (req, res) => {
  const BASE_DIR = path.resolve('./public');
  const requested = path.resolve(BASE_DIR, req.query.name || '');
  if (!requested.startsWith(BASE_DIR)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.sendFile(requested);
});
`,
  },
  python: {
    vulnerable: `# ⚠️  VULNERABLE Python — DO NOT USE IN PRODUCTION
import sqlite3
import subprocess
import pickle
import yaml
import hashlib

# Hardcoded secrets — never do this
DB_PASSWORD = "admin123"
SECRET_KEY  = "hardcoded_secret_key_xK9mP2"
API_TOKEN   = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SQL Injection: f-string in query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def run_command(user_input):
    # Command injection: shell=True with user input
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout

def load_data(data_bytes):
    # Insecure deserialization
    return pickle.loads(data_bytes)

def load_config(yaml_string):
    # yaml.load without SafeLoader
    return yaml.load(yaml_string)

def hash_password(password):
    # Weak hash — MD5 is broken
    return hashlib.md5(password.encode()).hexdigest()

def search_users(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL injection via concatenation
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchall()
`,
    safe: `# ✅ SECURE Python — production-ready patterns
import sqlite3
import subprocess
import hashlib
import secrets
import os
import yaml
from argon2 import PasswordHasher

# ✅ All secrets from environment variables
DB_PASSWORD = os.environ.get("DB_PASSWORD")
SECRET_KEY  = os.environ.get("SECRET_KEY")
API_TOKEN   = os.environ.get("API_TOKEN")

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # ✅ Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

def run_command(filename):
    # ✅ execFile equivalent — no shell interpolation
    allowed = {"report.txt", "summary.csv"}
    if filename not in allowed:
        raise ValueError("Invalid filename")
    result = subprocess.run(["cat", filename], capture_output=True, text=True)
    return result.stdout

def load_config(yaml_string):
    # ✅ SafeLoader prevents code execution
    return yaml.safe_load(yaml_string)

def hash_password(password: str) -> str:
    # ✅ Argon2 — modern, memory-hard password hashing
    ph = PasswordHasher()
    return ph.hash(password)

def generate_token() -> str:
    # ✅ Cryptographically secure random token
    return secrets.token_hex(32)

def search_users(name: str):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # ✅ Parameterized query
    cursor.execute("SELECT id, name FROM users WHERE name = ?", (name,))
    return cursor.fetchall()
`,
  },
  java: {
    vulnerable: `// ⚠️  VULNERABLE Java — DO NOT USE IN PRODUCTION
import java.sql.*;
import java.io.*;
import java.security.MessageDigest;

public class VulnerableApp {
    
    // Hardcoded credentials
    private static final String DB_URL      = "jdbc:mysql://localhost/app";
    private static final String DB_USER     = "root";
    private static final String DB_PASSWORD = "root_password_123";
    private static final String API_SECRET  = "AKIAIOSFODNN7EXAMPLE";

    public static User getUser(String userId) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt  = conn.createStatement();

        // SQL Injection: string concatenation in JDBC
        String query = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(query);
        return mapToUser(rs);
    }

    public static String runCommand(String userInput) throws Exception {
        // Command injection: Runtime.exec with user input
        Process p = Runtime.getRuntime().exec("ls " + userInput);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        return br.readLine();
    }

    public static String hashPassword(String password) throws Exception {
        // Weak hash — MD5 is cryptographically broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }

    public static void writeFile(String filename, String content) throws Exception {
        // Path traversal: filename from user input
        FileWriter fw = new FileWriter("../uploads/" + filename);
        fw.write(content);
        fw.close();
    }
}
`,
    safe: `// ✅ SECURE Java — production-ready patterns
import java.sql.*;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class SecureApp {

    // ✅ Credentials from environment / config — never hardcode
    private static final String DB_URL  = System.getenv("DB_URL");
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_PASS = System.getenv("DB_PASS");

    public static User getUser(String userId) throws Exception {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)) {
            // ✅ PreparedStatement — no SQL injection possible
            String sql = "SELECT id, name, email FROM users WHERE id = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, userId);
            ResultSet rs = pstmt.executeQuery();
            return mapToUser(rs);
        }
    }

    public static String runCommand(String filename) throws Exception {
        // ✅ Whitelist approach — never pass user input to shell
        Set<String> allowed = Set.of("report.txt", "summary.csv");
        if (!allowed.contains(filename)) throw new SecurityException("Disallowed file");
        ProcessBuilder pb = new ProcessBuilder("cat", filename); // args array, no shell
        Process p = pb.start();
        return new String(p.getInputStream().readAllBytes());
    }

    public static String hashPassword(String password) {
        // ✅ BCrypt — adaptive, salted, secure
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        return encoder.encode(password);
    }

    public static void writeFile(String filename, String content) throws Exception {
        // ✅ Path traversal prevention
        Path base      = Path.of("/app/uploads").toRealPath();
        Path requested = base.resolve(filename).normalize();
        if (!requested.startsWith(base)) throw new SecurityException("Path traversal detected");
        Files.writeString(requested, content);
    }

    public static String generateToken() {
        // ✅ Cryptographically secure random
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return java.util.HexFormat.of().formatHex(bytes);
    }
}
`,
  },
};

export const LANGUAGES = [
  { value: 'javascript', label: 'JavaScript', icon: 'JS' },
  { value: 'python',     label: 'Python',     icon: 'PY' },
  { value: 'java',       label: 'Java',       icon: 'JV' },
];
