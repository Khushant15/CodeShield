/**
 * services/aiService.js
 * AI-powered security analysis via Anthropic (Claude) or Groq.
 *
 * KEY DESIGN: AI does a FULL independent analysis of the code, NOT just
 * "fill in what static missed." This gives much better results when
 * static analysis has blind spots for the user's code style.
 */
const config = require('../config');
const logger  = require('../utils/logger');

// ── Current Groq models (updated 2024) ───────────────────────────────────────
// llama3-70b-8192 is deprecated — use these instead:
const GROQ_MODELS = [
  'llama-3.3-70b-versatile',   // best quality
  'llama-3.1-70b-versatile',   // fallback
  'llama3-groq-70b-8192-tool-use-preview', // tool-use variant
];

function buildPrompt(code, language, staticIssues) {
  const staticSummary = staticIssues.length
    ? staticIssues.map((i) => `  Line ${i.line}: [${i.severity}] ${i.type}`).join('\n')
    : '  (none found by static analysis)';

  return `You are a world-class application security engineer performing a thorough code security audit.

TASK: Analyze the ${language} code below and identify ALL security vulnerabilities.

Static analysis already flagged:
${staticSummary}

Your job:
1. Find ALL vulnerabilities — including ones static analysis missed
2. Be thorough: check for injection, XSS, auth issues, insecure config, secrets, unsafe functions, etc.
3. For EACH vulnerability, identify the exact line number

Return a JSON array. Each item MUST have EXACTLY these fields:
{
  "type": "e.g. SQL Injection / XSS / Hardcoded Secret / Command Injection / IDOR / SSRF / etc.",
  "severity": "High" or "Medium" or "Low",
  "line": <integer line number, 0 if unknown>,
  "snippet": "<the actual vulnerable line or expression, max 120 chars>",
  "explanation": "<1-2 sentences explaining why this is dangerous>",
  "fix": "<concrete fix — include corrected code example when possible>"
}

Rules:
- Return ONLY the raw JSON array — no markdown, no explanation text outside the array
- If you find no issues at all, return []
- Do NOT repeat an issue if it's the same type AND same line as a static result
- Be precise about line numbers — count from line 1

CODE TO ANALYZE (${language}):
\`\`\`${language}
${code.slice(0, 10000)}
\`\`\``;
}

// ── Anthropic ────────────────────────────────────────────────────────────────
async function callAnthropic(prompt) {
  const Anthropic = require('@anthropic-ai/sdk');
  const client = new Anthropic({ apiKey: config.ai.anthropicApiKey });
  const message = await client.messages.create({
    model: config.ai.anthropicModel,
    max_tokens: 4096,
    messages: [{ role: 'user', content: prompt }],
  });
  return message.content?.[0]?.text || '[]';
}

// ── Groq ─────────────────────────────────────────────────────────────────────
async function callGroq(prompt) {
  // Try each model in order until one works
  for (const model of GROQ_MODELS) {
    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.ai.groqApiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'system',
              content: 'You are a security code auditor. You ONLY output valid JSON arrays. No markdown, no explanation, just the JSON array.',
            },
            { role: 'user', content: prompt },
          ],
          max_tokens: 4096,
          temperature: 0.1,
          response_format: { type: 'text' }, // some Groq models support json_object
        }),
      });

      if (response.status === 404 || response.status === 400) {
        logger.warn(`Groq model ${model} unavailable, trying next...`);
        continue; // try the next model
      }

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`Groq API ${response.status}: ${body.slice(0, 200)}`);
      }

      const data = await response.json();
      const text = data.choices?.[0]?.message?.content;
      if (!text) throw new Error('Groq returned empty content');

      logger.debug(`Groq responded using model: ${model}`);
      return text;
    } catch (err) {
      if (err.message.includes('404') || err.message.includes('model')) {
        logger.warn(`Groq model ${model} failed: ${err.message}`);
        continue;
      }
      throw err;
    }
  }
  throw new Error('All Groq models failed — check your API key and account status');
}

// ── Parse AI response robustly ────────────────────────────────────────────────
function parseAIResponse(text) {
  if (!text) return [];

  // Remove markdown fences
  let clean = text
    .replace(/```(?:json)?\s*/gi, '')
    .replace(/```\s*/g, '')
    .trim();

  // Try direct parse
  try {
    const parsed = JSON.parse(clean);
    return Array.isArray(parsed) ? parsed : (parsed.issues || parsed.vulnerabilities || []);
  } catch { /* fall through */ }

  // Extract first JSON array from anywhere in the text
  const arrayMatch = clean.match(/\[\s*\{[\s\S]*?\}\s*\]/);
  if (arrayMatch) {
    try { return JSON.parse(arrayMatch[0]); } catch { /* fall through */ }
  }

  // Extract first JSON object and wrap in array
  const objMatch = clean.match(/\{[\s\S]*?\}/);
  if (objMatch) {
    try {
      const obj = JSON.parse(objMatch[0]);
      return Array.isArray(obj) ? obj : [obj];
    } catch { /* fall through */ }
  }

  logger.warn('Could not parse AI response as JSON', { preview: text.slice(0, 300) });
  return [];
}

// ── Sanitize + stamp a single AI issue ───────────────────────────────────────
let _aiCounter = 1;
function sanitizeIssue(raw) {
  return {
    id:          `AI_${String(_aiCounter++).padStart(3, '0')}`,
    type:        typeof raw.type        === 'string' ? raw.type.slice(0, 80)  : 'Security Issue',
    severity:    ['High', 'Medium', 'Low'].includes(raw.severity) ? raw.severity : 'Medium',
    line:        Number.isInteger(Number(raw.line)) ? Number(raw.line) : 0,
    snippet:     typeof raw.snippet     === 'string' ? raw.snippet.slice(0, 200) : '',
    explanation: typeof raw.explanation === 'string' ? raw.explanation : '',
    fix:         typeof raw.fix         === 'string' ? raw.fix : '',
    source:      'ai',
  };
}

// ── Main export ───────────────────────────────────────────────────────────────
/**
 * Run AI analysis. Returns array of issues.
 * @param {string}   code
 * @param {string}   language
 * @param {object[]} staticIssues  — passed for context only, AI does full scan
 * @returns {Promise<object[]>}
 */
async function runAIAnalysis(code, language, staticIssues) {
  const provider = config.ai.provider;
  _aiCounter = 1; // reset per request

  if (provider === 'none') {
    logger.debug('AI_PROVIDER=none — skipping AI analysis');
    return [];
  }

  if (provider === 'anthropic' && !config.ai.anthropicApiKey) {
    logger.warn('AI_PROVIDER=anthropic but ANTHROPIC_API_KEY not set');
    return [];
  }
  if (provider === 'groq' && !config.ai.groqApiKey) {
    logger.warn('AI_PROVIDER=groq but GROQ_API_KEY not set');
    return [];
  }

  const prompt = buildPrompt(code, language, staticIssues);
  logger.info(`Running AI analysis via ${provider}`);

  let rawText;
  try {
    rawText = provider === 'groq' ? await callGroq(prompt) : await callAnthropic(prompt);
  } catch (err) {
    logger.error(`AI provider call failed (${provider})`, { error: err.message });
    // Surface the error to the response so users know what went wrong
    return [{
      id: 'AI_ERR',
      type: 'AI Analysis Error',
      severity: 'Low',
      line: 0,
      snippet: '',
      explanation: `AI analysis failed: ${err.message}`,
      fix: 'Check that your API key is valid and the AI_PROVIDER setting matches your key type.',
      source: 'ai-error',
    }];
  }

  const parsed = parseAIResponse(rawText);
  logger.info(`AI returned ${parsed.length} issues`);

  return parsed
    .filter((i) => i && typeof i === 'object')
    .map(sanitizeIssue);
}

module.exports = { runAIAnalysis };
