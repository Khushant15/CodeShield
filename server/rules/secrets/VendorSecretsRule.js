/**
 * rules/secrets/VendorSecretsRule.js
 *
 * Layer-1 detection: precise vendor-specific key signatures.
 * Each pattern matches a known key format (AWS, GitHub, Stripe, etc.).
 * Very low false-positive rate.
 */

'use strict';

const BaseRule = require('../base/BaseRule');

/** @type {Array<{regex: RegExp, vendor: string}>} */
const VENDOR_PATTERNS = [
  { regex: /sk-[a-zA-Z0-9]{20,}/g,                             vendor: 'OpenAI API key' },
  { regex: /sk-ant-[a-zA-Z0-9\-]{30,}/g,                       vendor: 'Anthropic API key' },
  { regex: /AKIA[0-9A-Z]{16}/g,                                 vendor: 'AWS Access Key ID' },
  { regex: /ghp_[a-zA-Z0-9]{36}/g,                             vendor: 'GitHub Personal Access Token' },
  { regex: /gho_[a-zA-Z0-9]{36}/g,                             vendor: 'GitHub OAuth Token' },
  { regex: /ghs_[a-zA-Z0-9]{36}/g,                             vendor: 'GitHub App Token' },
  { regex: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g,                  vendor: 'Slack API token' },
  { regex: /AIza[0-9A-Za-z\-_]{35}/g,                          vendor: 'Google API key' },
  { regex: /SG\.[a-zA-Z0-9_\-.]{22,}\.[a-zA-Z0-9_\-.]{43}/g,  vendor: 'SendGrid API key' },
  { regex: /sk_live_[a-zA-Z0-9]{24,}/g,                        vendor: 'Stripe live secret key' },
  { regex: /rk_live_[a-zA-Z0-9]{24,}/g,                        vendor: 'Stripe restricted key' },
  { regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, vendor: 'PEM private key block' },
  { regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, vendor: 'Hardcoded JWT token' },
  { regex: /[0-9a-f]{32}-us[0-9]+/g,                           vendor: 'Mailchimp API key' },
  { regex: /Bearer\s+[a-zA-Z0-9\-._~+/]{20,}/g,               vendor: 'Hardcoded Bearer token' },
  { regex: /gsk_[a-zA-Z0-9]{40,}/g,                            vendor: 'Groq API key' },
];

class VendorSecretsRule extends BaseRule {
  constructor() {
    super('VSECRET', 'Hardcoded Vendor Secret');
  }

  /**
   * @param {import('../base/BaseRule').ParsedContext} context
   * @returns {import('../base/BaseRule').Issue[]}
   */
  analyze(context) {
    const { lines } = context;
    const issues = [];

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      // Skip blank lines, comments, import/require statements
      if (this._isComment(trimmed)) return;
      if (/^\s*(?:import|require|from|use)\s/.test(trimmed)) return;

      for (const { regex, vendor } of VENDOR_PATTERNS) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          const redacted = trimmed
            .replace(/(['"`])[^'"`]{4,}(['"`])/g, '$1[REDACTED]$2')
            .slice(0, 200);

          issues.push(
            this._buildIssue(
              'Hardcoded Secret',
              'High',
              idx + 1,
              redacted,
              `${vendor} found hardcoded in source. This secret is exposed to anyone with repo access ` +
              `or in git history — even after deletion.`,
              'Remove immediately from source code. Rotate the leaked credential.\n' +
              'Store secrets in environment variables:\n' +
              '  process.env.MY_SECRET   // Node.js\n' +
              '  os.environ.get("MY_SECRET")  // Python\n' +
              'Use a secrets manager (AWS Secrets Manager, Vault) in production.'
            )
          );
          return; // one issue per line
        }
      }
    });

    return issues;
  }
}

module.exports = VendorSecretsRule;
