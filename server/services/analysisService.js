/**
 * services/analysisService.js
 * Orchestrates static + AI analysis pipelines.
 */
const { runStaticAnalysis } = require('../analyzers');
const { runAIAnalysis }     = require('./aiService');
const { calculateScore }    = require('../utils/scoreCalculator');
const logger                = require('../utils/logger');

/**
 * Main entry point for code analysis.
 * @param {string} code
 * @param {string} language
 * @returns {Promise<{score: number, issues: object[], analysisTime: number}>}
 */
async function analyzeCode(code, language) {
  const start = Date.now();
  logger.info('Starting analysis', { language, codeLength: code.length });

  // 1. Static analysis (synchronous, fast)
  const staticIssues = runStaticAnalysis(code, language);
  logger.debug('Static analysis complete', { found: staticIssues.length });

  // 2. AI-enhanced analysis (async, optional)
  const aiIssues = await runAIAnalysis(code, language, staticIssues);
  logger.debug('AI analysis complete', { found: aiIssues.length });

  // 3. Merge: AI issues that aren't duplicates of static ones
  const staticKeys = new Set(staticIssues.map((i) => `${i.line}::${i.type}`));
  const uniqueAiIssues = aiIssues.filter((i) => !staticKeys.has(`${i.line}::${i.type}`));

  const allIssues = [...staticIssues, ...uniqueAiIssues]
    .sort((a, b) => {
      const sev = { Critical: -1, High: 0, Medium: 1, Low: 2 };
      return (sev[a.severity] ?? 3) - (sev[b.severity] ?? 3) || a.line - b.line;
    });

  // 4. Score
  const score = calculateScore(allIssues);
  const analysisTime = Date.now() - start;

  logger.info('Analysis complete', { totalIssues: allIssues.length, score, analysisTime });

  return { score, issues: allIssues, analysisTime };
}

module.exports = { analyzeCode };
