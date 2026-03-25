/**
 * API Key Authentication Middleware (Optional)
 * If API_KEY env var is set, all /api requests must include X-API-Key header.
 */

export function apiKeyAuth(req, res, next) {
  const configuredKey = process.env.API_KEY;

  // If no API key is configured, skip authentication entirely
  if (!configuredKey) return next();

  const providedKey = req.headers['x-api-key'];

  if (!providedKey) {
    console.warn(`[AUTH] Missing API key from IP ${req.ip} at ${new Date().toISOString()}`);
    return res.status(401).json({ error: 'API key required. Include X-API-Key header.' });
  }

  // Constant-time comparison to prevent timing attacks
  if (!timingSafeEqual(configuredKey, providedKey)) {
    console.warn(`[AUTH] Invalid API key from IP ${req.ip} at ${new Date().toISOString()}`);
    return res.status(403).json({ error: 'Invalid API key.' });
  }

  next();
}

/**
 * Timing-safe string comparison to mitigate timing attacks.
 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
