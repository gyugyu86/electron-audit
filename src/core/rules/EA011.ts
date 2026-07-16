import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { collectCspStrings, findUnsafeCspHits } from './shared/cspSites.js';

const WHY_DANGEROUS =
  "'unsafe-inline' or 'unsafe-eval' in a CSP allows inline script/style or eval-family execution. unsafe-inline in " +
  "a script-execution directive (script-src/default-src), and unsafe-eval anywhere, are an XSS-to-code-execution " +
  "path and are reported at high; unsafe-inline in other directives (style-src, etc.) has a more limited attack " +
  "surface and is reported at medium.";

const RECOMMENDATION = `Remove 'unsafe-inline'/'unsafe-eval', and allow specific inline content individually via a nonce or hash instead.

// vulnerable
"script-src 'self' 'unsafe-inline' 'unsafe-eval'"

// fixed
"script-src 'self' 'nonce-<generated-per-request>'"`;

// Aggregate (not per-file): the CSP surface now spans JS response-header sites
// AND HTML <meta> tags, so it's judged project-wide from the unified
// collectCspStrings list. Token-based, never a raw substring scan: a host or
// comment that happens to contain "unsafe-inline" must not trigger this —
// only an exact source token does. Severity is directive-graded (see
// findUnsafeCspHits) so declared severity here is the max the rule can emit.
export const EA011: AggregateRule = {
  id: 'EA011',
  kind: 'aggregate',
  severity: 'high',
  target: "CSP 'unsafe-inline' / 'unsafe-eval'",
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const csp of collectCspStrings(context)) {
      for (const hit of findUnsafeCspHits(csp.value)) {
        findings.push({
          ruleId: 'EA011',
          severity: hit.severity,
          confidence: 'high',
          file: csp.file,
          line: csp.line,
          target: `${hit.directive} has ${hit.keywords.join(', ')}`,
          whyDangerous: WHY_DANGEROUS,
          recommendation: RECOMMENDATION,
        });
      }
    }

    return findings;
  },
};
