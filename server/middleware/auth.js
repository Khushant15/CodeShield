/**
 * middleware/auth.js
 * Optional API key protection for the /analyze endpoint.
 * If API_KEY env var is set, clients must send header: x-api-key: <value>
 */
const config = require('../config');
const logger = require('../utils/logger');

function apiKeyAuth(req, res, next) {
  // If no API key is configured, skip authentication
  if (!config.security.apiKey) return next();

  const provided = req.headers['x-api-key'];
  if (!provided || provided !== config.security.apiKey) {
    logger.warn('Unauthorized API access attempt', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Unauthorized — invalid or missing API key.' });
  }
  next();
}

module.exports = { apiKeyAuth };
