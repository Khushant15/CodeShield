/**
 * routes/health.js — Health check + configuration debug endpoint
 */
const express = require('express');
const config  = require('../config');
const router  = express.Router();

// GET /health — basic liveness check
router.get('/', (_req, res) => {
  const provider = config.ai.provider;
  const hasKey =
    provider === 'anthropic' ? !!config.ai.anthropicApiKey :
    provider === 'groq'      ? !!config.ai.groqApiKey :
    false;

  res.json({
    status:      'ok',
    version:     '1.0.0',
    env:         config.nodeEnv,
    aiProvider:  provider,
    aiKeySet:    hasKey,
    timestamp:   new Date().toISOString(),
  });
});

// GET /health/debug — detailed config state (dev only, never expose in prod)
router.get('/debug', (req, res) => {
  if (config.nodeEnv === 'production') {
    return res.status(403).json({ error: 'Debug endpoint disabled in production.' });
  }
  res.json({
    AI_PROVIDER:       config.ai.provider,
    ANTHROPIC_KEY_SET: !!config.ai.anthropicApiKey,
    GROQ_KEY_SET:      !!config.ai.groqApiKey,
    ALLOWED_ORIGINS:   config.security.allowedOrigins,
    RATE_LIMIT_MAX:    config.rateLimit.max,
    MAX_PAYLOAD:       config.maxPayloadSize,
  });
});

module.exports = router;
