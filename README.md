![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![React](https://img.shields.io/badge/Frontend-React-blue)
![Node.js](https://img.shields.io/badge/Backend-Node.js-green)
![Security](https://img.shields.io/badge/Focus-Security-red)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
# 🛡️ CodeShield — AI-Powered Security Vulnerability Analyzer

A production-quality web application that analyzes JavaScript, Python, and Java source code for security vulnerabilities with precise line numbers, explanations, and fixes.

---

## ✨ Features

- **Monaco Editor** (VS Code) with syntax highlighting and vulnerable line marking
- **4 Static Analyzers**: SQL Injection · XSS · Hardcoded Secrets · Unsafe Patterns
- **AI Deep Analysis** via Anthropic Claude or Groq (optional — app works without it)
- **Security Score** (0–100) with severity-weighted deductions
- **Precise line detection** — exact snippet + surrounding context
- **Dark cybersecurity UI** with color-coded severity badges
- **Full security hardening**: Helmet, CORS, rate limiting, Joi validation, size limits

---

## 📁 Project Structure

```
codeshield/
├── package.json              ← root (concurrently dev runner)
│
├── server/                   ← Express API
│   ├── index.js              ← app entry point
│   ├── .env.example          ← copy to .env and fill in
│   ├── config/
│   │   └── index.js          ← centralised env config
│   ├── routes/
│   │   ├── analyze.js        ← POST /analyze
│   │   └── health.js         ← GET /health
│   ├── controllers/
│   │   └── analyzeController.js
│   ├── services/
│   │   ├── analysisService.js  ← orchestrates static + AI
│   │   └── aiService.js        ← Anthropic / Groq client
│   ├── analyzers/
│   │   ├── index.js            ← aggregator (splits lines ONCE)
│   │   ├── sqlInjection.js
│   │   ├── xss.js
│   │   ├── secrets.js
│   │   └── unsafePatterns.js
│   ├── middleware/
│   │   ├── rateLimiter.js
│   │   ├── validate.js         ← Joi schema validation
│   │   ├── auth.js             ← optional API key protection
│   │   └── errorHandler.js
│   └── utils/
│       ├── logger.js           ← Winston structured logging
│       └── scoreCalculator.js
│
└── client/                   ← React + Vite + Tailwind
    ├── index.html
    ├── vite.config.js         ← proxies /analyze → :4000
    ├── tailwind.config.js
    ├── .env.example
    └── src/
        ├── main.jsx
        ├── App.jsx             ← root component + state
        ├── index.css
        ├── components/
        │   ├── Header.jsx
        │   ├── CodeEditor.jsx  ← Monaco with line decorations
        │   ├── LanguageSelector.jsx
        │   ├── Toolbar.jsx
        │   ├── ResultsPanel.jsx
        │   ├── IssueCard.jsx
        │   ├── ScoreGauge.jsx
        │   ├── SeverityBreakdown.jsx
        │   ├── ScanAnimation.jsx
        │   └── Toast.jsx
        ├── services/
        │   └── api.js          ← Axios client
        ├── hooks/
        │   └── useToast.js
        └── utils/
            └── samples.js      ← vulnerable + safe examples
```

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** ≥ 18
- An **Anthropic** or **Groq** API key (optional — static analysis works without one)

---

### 1. Clone / unzip the project

```bash
cd codeshield
```

### 2. Install all dependencies

```bash
# Install root + server + client packages
npm install
npm install --prefix server
npm install --prefix client
```

### 3. Configure the server environment

```bash
cp server/.env.example server/.env
```

Open `server/.env` and set your values:

```env
PORT=4000
NODE_ENV=development

# Choose ONE:
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-api03-...

# OR:
# AI_PROVIDER=groq
# GROQ_API_KEY=gsk_...

# Set to 'none' to use only static analysis (no API key needed)
# AI_PROVIDER=none

ALLOWED_ORIGINS=http://localhost:5173
```

### 4. Configure the client environment (optional)

```bash
cp client/.env.example client/.env
# Leave VITE_API_URL blank — Vite proxy handles it automatically
```

### 5. Run both servers together

```bash
npm run dev
```

This starts:
- **API server** on http://localhost:4000
- **React app** on http://localhost:5173

Open http://localhost:5173 in your browser.

---

### Run servers separately (alternative)

```bash
# Terminal 1 — Backend
npm run dev:server

# Terminal 2 — Frontend
npm run dev:client
```

---

## 🔌 API Reference

### `POST /analyze`

**Headers:** `Content-Type: application/json`
(add `x-api-key: <value>` if `API_KEY` env var is set)

**Request body:**
```json
{
  "code": "const query = 'SELECT * FROM users WHERE id = ' + userId;",
  "language": "javascript"
}
```
Supported languages: `javascript` · `python` · `java`

**Response:**
```json
{
  "success": true,
  "language": "javascript",
  "score": 80,
  "issueCount": 1,
  "analysisTime": 142,
  "issues": [
    {
      "id": "SQL_001",
      "type": "SQL Injection",
      "severity": "High",
      "line": 1,
      "snippet": "const query = 'SELECT * FROM users WHERE id = ' + userId;",
      "explanation": "SQL string literal concatenated with a variable — classic injection vector.",
      "fix": "Use parameterized queries:\n  db.query(\"SELECT * FROM users WHERE id = $1\", [userId])"
    }
  ]
}
```

### `GET /health`

Returns server status, version, and active AI provider.

---

## 🧪 Test Cases

### Vulnerable JavaScript (paste into editor or click "Load Sample → Vulnerable Code")

```javascript
const DB_PASS = "hardcoded_password_123";
const query = "SELECT * FROM users WHERE id = " + req.query.id;
document.getElementById('out').innerHTML = userInput;
eval(req.body.script);
```

Expected: **4+ issues**, score ≤ 20

### Safe JavaScript

```javascript
const secret = process.env.SECRET_KEY;
const [rows] = await db.query("SELECT * FROM users WHERE id = ?", [userId]);
document.getElementById('out').textContent = sanitize(userInput);
```

Expected: **0 issues**, score = 100

---

## 🔐 Security Controls (the app secures itself)

| Control | Implementation |
|---|---|
| HTTP security headers | `helmet` middleware |
| CORS | Allowlist-only origins |
| Rate limiting | 50 req / 15 min per IP |
| Input validation | `joi` schema on all inputs |
| Payload size cap | 500 KB max request body |
| Optional API key auth | `x-api-key` header check |
| Safe error responses | Stack traces hidden in production |
| Structured logging | `winston` — suspicious activity flagged |
| No hardcoded secrets | All config via environment variables |

---

## 🧠 Detection Engine

```
Code input
    │
    ├─ Split lines ONCE (O(n)) ──────────────────────────────────────────┐
    │                                                                     │
    ├─ sqlInjection.js   ← precompiled regex, no re-split               │
    ├─ xss.js            ← precompiled regex, no re-split               │  reuse
    ├─ secrets.js        ← vendor patterns + var-name heuristic         │  same
    ├─ unsafePatterns.js ← 15 patterns: eval, exec, path traversal...   │  array
    │                                                                     │
    └─ Merge + deduplicate ──────────────────────────────────────────────┘
         │
         └─ AI layer (Anthropic / Groq) — async, fails gracefully
              │
              └─ Score calculation → Response
```

**Adding a new analyzer:**

1. Create `server/analyzers/myCheck.js` exporting `{ analyze(lines, language) }`
2. Add one line in `server/analyzers/index.js`:
   ```js
   const myCheck = require('./myCheck');
   const ANALYZERS = [..., { name: 'MyCheck', module: myCheck }];
   ```

---

## 📊 Score Calculation

| Severity | Deduction |
|---|---|
| High | −20 points |
| Medium | −10 points |
| Low | −5 points |
| Floor | 0 (never negative) |

| Score Range | Grade |
|---|---|
| 80–100 | ✅ Secure |
| 60–79  | ⚠️ Moderate Risk |
| 40–59  | 🔶 High Risk |
| 0–39   | 🔴 Critical |

---

## 🛠️ Troubleshooting

**"Backend offline" toast on startup**
→ Make sure `npm run dev:server` is running and `server/.env` is configured.

**Monaco editor not loading**
→ Run `npm install --prefix client` to ensure `@monaco-editor/react` is installed.

**AI analysis not appearing**
→ Check that `ANTHROPIC_API_KEY` or `GROQ_API_KEY` is set in `server/.env` and `AI_PROVIDER` matches.

**Rate limit hit (429)**
→ Increase `RATE_LIMIT_MAX` in `server/.env` for local development.

---

## 📦 Production Build

```bash
# Build the React app
npm run build

# Serve static files from server (add static middleware to index.js)
# Or deploy client/dist/ to Vercel/Netlify and server/ to Railway/Render
```

---

## License
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
MIT — use freely, credit appreciated.
