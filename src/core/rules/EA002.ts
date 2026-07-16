import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { classifyMissingSecureDefault } from './shared/webPreferencesAbsence.js';

// contextIsolation's secure default (true) took effect in Electron 12.
const CONTEXT_ISOLATION_SAFE_SINCE = 12;

const WHY_DANGEROUS =
  'With contextIsolation off, the preload script and the renderer page share the same JS context. A malicious ' +
  'script on the page can hijack objects the preload exposed, or Electron internals, via prototype pollution and ' +
  'similar techniques, to escalate its privileges.';

const RECOMMENDATION = `Turn contextIsolation on (keep the default) and expose APIs from preload only through contextBridge.

const win = new BrowserWindow({
  webPreferences: {
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});`;

export const EA002: NodeRule = {
  id: 'EA002',
  kind: 'node',
  severity: 'critical',
  target: 'BrowserWindow webPreferences.contextIsolation',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const site of getWindowCallSites(context.ast, context.file.path)) {
      const state = site.webPreferences.contextIsolation.state;
      const base = { ruleId: 'EA002', severity: 'critical', file: site.file, line: site.line, recommendation: RECOMMENDATION } as const;

      if (state === 'explicit-false') {
        findings.push({ ...base, confidence: 'high', target: 'contextIsolation: false', whyDangerous: WHY_DANGEROUS });
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          confidence: 'heuristic',
          target: 'contextIsolation: <variable/expression>',
          whyDangerous: `${WHY_DANGEROUS} (The value is a variable/expression, so it could be turned off at runtime.)`,
        });
      } else if (state === 'absent') {
        const verdict = classifyMissingSecureDefault(context.project.electronMajorVersion, CONTEXT_ISOLATION_SAFE_SINCE);
        if (verdict.report) {
          findings.push({
            ...base,
            confidence: 'heuristic',
            target: 'contextIsolation not set',
            whyDangerous: `${WHY_DANGEROUS} ${verdict.reason}`,
          });
        }
      }
    }

    return findings;
  },
};
