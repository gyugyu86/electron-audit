import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCspHeaderSites } from './shared/cspSites.js';
import { tokenizeCsp } from '../csp/cspTokenizer.js';

const WHY_DANGEROUS =
  'The CSP still contains the `gap:` scheme used by Cordova/hybrid apps. This is less a vulnerability than a sign ' +
  "that a CSP was pasted in from another project — check whether this app actually needs it.";

const RECOMMENDATION = `Remove Cordova leftovers (\`gap:\` and similar) that an Electron app doesn't need, and keep only the sources this app actually requires.`;

// info-level, high-confidence (the token is unambiguously present). Kept
// narrow to a clear Cordova signature (`gap:`) to avoid over-flagging.
export const EA013: NodeRule = {
  id: 'EA013',
  kind: 'node',
  severity: 'info',
  target: 'CSP has a Cordova leftover (`gap:`) signature',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const site of findCspHeaderSites(context.ast)) {
      for (const value of site.values) {
        for (const directive of tokenizeCsp(value)) {
          if (directive.sources.some((source) => source.toLowerCase().startsWith('gap:'))) {
            findings.push({
              ruleId: 'EA013',
              severity: 'info',
              confidence: 'high',
              file: context.file.path,
              line: site.line,
              target: `${directive.name} has \`gap:\` (Cordova leftover)`,
              whyDangerous: WHY_DANGEROUS,
              recommendation: RECOMMENDATION,
            });
          }
        }
      }
    }

    return findings;
  },
};
