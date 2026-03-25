/**
 * middleware/rateLimiter.js
 * Express-rate-limit: prevents brute force / spam API calls.
 */
const rateLimit = require('express-rate-limit');
const config = require('../config');
const logger = require('../utils/logger');

const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', { ip: req.ip, path: req.path });
    res.status(429).json({
      error: 'Too many requests — please slow down and try again later.',
      retryAfter: Math.ceil(config.rateLimit.windowMs / 1000),
    });
  },
});

module.exports = limiter;
