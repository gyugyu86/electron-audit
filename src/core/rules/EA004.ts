import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

const WHY_DANGEROUS =
  'webSecurity: false disables the same-origin policy (SOP) and lets the page load and run remote resources ' +
  'indiscriminately. It removes XSS and data-exfiltration protections wholesale.';

const RECOMMENDATION = `Don't turn webSecurity off (keep the default of true). If you need to work around CORS during development, use a dedicated mechanism for that instead.

// vulnerable
new BrowserWindow({ webPreferences: { webSecurity: false } });

// fixed
new BrowserWindow({ webPreferences: { /* keep webSecurity at its default (true) */ } });`;

export const EA004: NodeRule = {
  id: 'EA004',
  kind: 'node',
  severity: 'high',
  target: 'BrowserWindow webPreferences.webSecurity',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    // webSecurity defaults to true regardless of version, so 'absent' is
    // safe — only an explicit false (or a dynamic value that could be false)
    // is a finding.
    for (const site of getWindowCallSites(context.ast, context.file.path)) {
      const state = site.webPreferences.webSecurity.state;
      const base = { ruleId: 'EA004', severity: 'high', file: site.file, line: site.line, recommendation: RECOMMENDATION } as const;

      if (state === 'explicit-false') {
        findings.push({ ...base, confidence: 'high', target: 'webSecurity: false', whyDangerous: WHY_DANGEROUS });
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          confidence: 'heuristic',
          target: 'webSecurity: <variable/expression>',
          whyDangerous: `${WHY_DANGEROUS} (The value is a variable/expression, so it could be turned off at runtime.)`,
        });
      }
    }

    return findings;
  },
};
