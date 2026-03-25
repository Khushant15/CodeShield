/**
 * config/index.js — Centralised environment-driven configuration
 */
require('dotenv').config();

const config = {
  port:    parseInt(process.env.PORT, 10) || 4000,
  nodeEnv: process.env.NODE_ENV || 'development',

  ai: {
    // Default to 'none' so the app works without any API key
    // Set AI_PROVIDER=groq  + GROQ_API_KEY  for Groq
    // Set AI_PROVIDER=anthropic + ANTHROPIC_API_KEY for Claude
    provider:       (process.env.AI_PROVIDER || 'none').toLowerCase().trim(),
    anthropicApiKey: process.env.ANTHROPIC_API_KEY || '',
    groqApiKey:      process.env.GROQ_API_KEY      || '',
    anthropicModel:  process.env.ANTHROPIC_MODEL   || 'claude-opus-4-6',
    // groqModel is now tried in order inside aiService.js — no single value needed
  },

  security: {
    apiKey:         process.env.API_KEY || '',
    allowedOrigins: (process.env.ALLOWED_ORIGINS || 'http://localhost:5173,http://localhost:3000')
      .split(',').map((o) => o.trim()),
  },

  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
    max:      parseInt(process.env.RATE_LIMIT_MAX,        10) || 100,
  },

  maxPayloadSize: process.env.MAX_PAYLOAD_SIZE || '500kb',
};

module.exports = config;
