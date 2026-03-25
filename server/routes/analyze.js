/**
 * routes/analyze.js
 */
const express                    = require('express');
const { handleAnalyze }          = require('../controllers/analyzeController');
const { validateAnalyzeRequest } = require('../middleware/validate');
const { apiKeyAuth }             = require('../middleware/auth');
const logger                     = require('../utils/logger');

const router = express.Router();

// Log every incoming analysis request (helps debug user-submitted code issues)
router.use((req, _res, next) => {
  if (req.method === 'POST') {
    logger.debug('Analyze request', {
      language: req.body?.language,
      codeLength: req.body?.code?.length,
      ip: req.ip,
    });
  }
  next();
});

router.post('/', apiKeyAuth, validateAnalyzeRequest, handleAnalyze);

module.exports = router;
