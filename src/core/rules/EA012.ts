import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { collectCspStrings, findWildcardCspDirectives } from './shared/cspSites.js';

const WHY_DANGEROUS =
  'A CSP directive whose source is a bare wildcard `*` allows every origin — no different in practice from having ' +
  'no CSP at all. Arbitrary remote scripts or resources can be loaded.';

const RECOMMENDATION = `List only the origins you actually need instead of \`*\`. If you need subdomains, pin the domain like \`*.example.com\`.

// vulnerable
"default-src *"

// fixed
"default-src 'self' https://api.example.com"`;

// Aggregate: judges the unified CSP surface (JS response headers + HTML
// <meta>). Exact-token match ONLY — a source token of exactly "*" allows every
// origin and is a finding; a partial wildcard like "*.foo.com" or
// "https://*.cdn.com" restricts to one domain's subdomains and is NOT — the
// whole reason CSP judgments tokenize first instead of running a `*` regex
// over the raw string.
export const EA012: AggregateRule = {
  id: 'EA012',
  kind: 'aggregate',
  severity: 'medium',
  target: 'CSP source is a wildcard `*` (allows every origin)',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const csp of collectCspStrings(context)) {
      for (const directive of findWildcardCspDirectives(csp.value)) {
        findings.push({
          ruleId: 'EA012',
          severity: 'medium',
          confidence: 'high',
          file: csp.file,
          line: csp.line,
          target: `${directive} has a wildcard \`*\``,
          whyDangerous: WHY_DANGEROUS,
          recommendation: RECOMMENDATION,
        });
      }
    }

    return findings;
  },
};
