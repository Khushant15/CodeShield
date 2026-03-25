/**
 * utils/logger.js
 * Winston-powered structured logger.
 * Logs to console in dev; structured JSON in production.
 */
const { createLogger, format, transports } = require('winston');
const config = require('../config');

const { combine, timestamp, printf, colorize, json } = format;

const devFormat = printf(({ level, message, timestamp: ts, ...meta }) => {
  const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
  return `${ts} [${level}]: ${message}${metaStr}`;
});

const logger = createLogger({
  level: config.nodeEnv === 'production' ? 'warn' : 'debug',
  format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss' })),
  transports: [
    config.nodeEnv === 'production'
      ? new transports.Console({ format: combine(timestamp(), json()) })
      : new transports.Console({ format: combine(colorize(), timestamp({ format: 'HH:mm:ss' }), devFormat) }),
  ],
});

module.exports = logger;
