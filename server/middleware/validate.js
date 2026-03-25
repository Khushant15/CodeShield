/**
 * middleware/validate.js
 * Joi-based input validation for /analyze endpoint.
 * Rejects malformed, oversized, or invalid requests before processing.
 */
const Joi = require('joi');

const SUPPORTED_LANGUAGES = ['javascript', 'python', 'java'];
const MAX_CODE_LENGTH = 50_000; // 50 KB of source text

const analyzeSchema = Joi.object({
  code: Joi.string().min(1).max(MAX_CODE_LENGTH).required().messages({
    'string.empty': 'Code cannot be empty.',
    'string.max': `Code must not exceed ${MAX_CODE_LENGTH} characters.`,
    'any.required': 'code field is required.',
  }),
  language: Joi.string()
    .lowercase()
    .valid(...SUPPORTED_LANGUAGES)
    .required()
    .messages({
      'any.only': `Language must be one of: ${SUPPORTED_LANGUAGES.join(', ')}.`,
      'any.required': 'language field is required.',
    }),
});

function validateAnalyzeRequest(req, res, next) {
  const { error, value } = analyzeSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      error: 'Validation failed',
      details: error.details.map((d) => d.message),
    });
  }
  // Attach sanitised / normalised values
  req.body = value;
  next();
}

module.exports = { validateAnalyzeRequest };
