/**
 * utils/scoreCalculator.js
 * Calculates a 0–100 security score from a list of issues.
 * Deductions: High → -20, Medium → -10, Low → -5 (capped at 0).
 */
const DEDUCTIONS = { High: 20, Medium: 10, Low: 5 };

/**
 * @param {Array<{severity: string}>} issues
 * @returns {number} score between 0 and 100
 */
function calculateScore(issues) {
  const total = issues.reduce((acc, issue) => {
    return acc - (DEDUCTIONS[issue.severity] || 0);
  }, 100);
  return Math.max(0, total);
}

/**
 * Returns a label and colour class for a given score.
 */
function scoreGrade(score) {
  if (score >= 80) return { label: 'Secure', colour: 'green' };
  if (score >= 60) return { label: 'Moderate Risk', colour: 'yellow' };
  if (score >= 40) return { label: 'High Risk', colour: 'orange' };
  return { label: 'Critical', colour: 'red' };
}

module.exports = { calculateScore, scoreGrade };
