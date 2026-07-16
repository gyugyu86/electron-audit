import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

const WHY_DANGEROUS =
  'allowRunningInsecureContent: true lets an https page run mixed content, such as scripts served over http. A ' +
  'man-in-the-middle attacker can swap out that http resource to run arbitrary code on the page.';

const RECOMMENDATION = `Don't turn allowRunningInsecureContent on (keep the default of false). Serve every resource over https.

// vulnerable
new BrowserWindow({ webPreferences: { allowRunningInsecureContent: true } });

// fixed
new BrowserWindow({ webPreferences: { /* keep allowRunningInsecureContent at its default (false) */ } });`;

export const EA005: NodeRule = {
  id: 'EA005',
  kind: 'node',
  severity: 'medium',
  target: 'BrowserWindow webPreferences.allowRunningInsecureContent',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    // This one defaults to false, so the danger is an explicit TRUE (or a
    // dynamic value that could be true), not an absence.
    for (const site of getWindowCallSites(context.ast, context.file.path)) {
      const state = site.webPreferences.allowRunningInsecureContent.state;
      const base = { ruleId: 'EA005', severity: 'medium', file: site.file, line: site.line, recommendation: RECOMMENDATION } as const;

      if (state === 'explicit-true') {
        findings.push({ ...base, confidence: 'high', target: 'allowRunningInsecureContent: true', whyDangerous: WHY_DANGEROUS });
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          confidence: 'heuristic',
          target: 'allowRunningInsecureContent: <variable/expression>',
          whyDangerous: `${WHY_DANGEROUS} (The value is a variable/expression, so it could be turned on at runtime.)`,
        });
      }
    }

    return findings;
  },
};
