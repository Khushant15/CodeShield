/**
 * index.js — CodeShield API Server
 * Entry point: wires middleware, routes, and starts listening.
 */
require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const morgan       = require('morgan');

const config       = require('./config');
const rateLimiter  = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');
const logger       = require('./utils/logger');

const analyzeRouter = require('./routes/analyze');
const healthRouter  = require('./routes/health');

const app = express();

// ── Security headers (helmet defaults are solid) ──────────────────────────────
app.use(helmet());

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(
  cors({
    origin: (origin, cb) => {
      // Allow requests with no origin (e.g. curl, Postman in dev)
      if (!origin || config.security.allowedOrigins.includes(origin)) {
        cb(null, true);
      } else {
        logger.warn('CORS blocked request', { origin });
        cb(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'x-api-key'],
  })
);

// ── Body parsing (with payload size limit) ────────────────────────────────────
app.use(express.json({ limit: config.maxPayloadSize }));
app.use(express.urlencoded({ extended: false, limit: config.maxPayloadSize }));

// ── HTTP request logging (skip in test) ──────────────────────────────────────
if (config.nodeEnv !== 'test') {
  app.use(morgan(config.nodeEnv === 'production' ? 'combined' : 'dev'));
}

// ── Global rate limiting ──────────────────────────────────────────────────────
app.use(rateLimiter);

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/health', healthRouter);
app.use('/analyze', analyzeRouter);

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// ── Central error handler (must be last) ─────────────────────────────────────
app.use(errorHandler);

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = config.port;
app.listen(PORT, () => {
  logger.info(`CodeShield API running on port ${PORT}`, {
    env: config.nodeEnv,
    aiProvider: config.ai.provider,
  });
});

module.exports = app; // export for testing
