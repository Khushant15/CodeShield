/**
 * controllers/analyzeController.js
 * Handles the POST /analyze request/response cycle.
 */
const { analyzeCode } = require('../services/analysisService');
const logger          = require('../utils/logger');

async function handleAnalyze(req, res, next) {
  try {
    const { code, language } = req.body; // already validated by middleware

    const result = await analyzeCode(code, language);

    return res.status(200).json({
      success: true,
      language,
      score: result.score,
      issueCount: result.issues.length,
      analysisTime: result.analysisTime,
      issues: result.issues,
      summary: result.summary,
    });
  } catch (err) {
    logger.error('Controller error in handleAnalyze', { message: err.message });
    next(err);
  }
}

module.exports = { handleAnalyze };
