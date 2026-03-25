/**
 * middleware/errorHandler.js
 * Central Express error handler — never exposes stack traces in production.
 */
const config = require('../config');
const logger = require('../utils/logger');

function errorHandler(err, req, res, _next) {
  logger.error('Unhandled error', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  const status = err.status || err.statusCode || 500;
  const body = {
    error: 'An internal error occurred.',
  };

  // Only leak details in development
  if (config.nodeEnv !== 'production') {
    body.detail = err.message;
  }

  res.status(status).json(body);
}

module.exports = errorHandler;
