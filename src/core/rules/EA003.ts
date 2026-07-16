import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { classifyMissingSecureDefault } from './shared/webPreferencesAbsence.js';

// sandbox's secure default (true) took effect in Electron 20.
const SANDBOX_SAFE_SINCE = 20;

const WHY_DANGEROUS =
  "With sandbox off, the renderer process runs outside the OS sandbox — if the renderer is compromised, an " +
  'attacker gets much easier access to Node and system resources. The sandbox is the primary containment for ' +
  'renderer compromise.';

const RECOMMENDATION = `Turn sandbox on (keep the default). Write preload to use only sandbox-compatible APIs.

const win = new BrowserWindow({
  webPreferences: {
    sandbox: true,
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});`;

export const EA003: NodeRule = {
  id: 'EA003',
  kind: 'node',
  severity: 'high',
  target: 'BrowserWindow webPreferences.sandbox',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const site of getWindowCallSites(context.ast, context.file.path)) {
      const state = site.webPreferences.sandbox.state;
      const base = { ruleId: 'EA003', severity: 'high', file: site.file, line: site.line, recommendation: RECOMMENDATION } as const;

      if (state === 'explicit-false') {
        findings.push({ ...base, confidence: 'high', target: 'sandbox: false', whyDangerous: WHY_DANGEROUS });
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          confidence: 'heuristic',
          target: 'sandbox: <variable/expression>',
          whyDangerous: `${WHY_DANGEROUS} (The value is a variable/expression, so it could be turned off at runtime.)`,
        });
      } else if (state === 'absent') {
        const verdict = classifyMissingSecureDefault(context.project.electronMajorVersion, SANDBOX_SAFE_SINCE);
        if (verdict.report) {
          findings.push({
            ...base,
            confidence: 'heuristic',
            target: 'sandbox not set',
            whyDangerous: `${WHY_DANGEROUS} ${verdict.reason}`,
          });
        }
      }
    }

    return findings;
  },
};
