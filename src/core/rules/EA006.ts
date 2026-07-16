import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { isClearlySafeWindow, isDangerousWindow } from './shared/windowSafety.js';

const WHY_DANGEROUS =
  'One window in this project is configured safely (contextIsolation on / nodeIntegration off) while another is ' +
  'configured dangerously. This usually happens when a team hardens the main window but forgets a child window\'s ' +
  '(e.g. an "open-win"-style) webPreferences — and an attacker goes after whichever window has the weaker defenses. ' +
  "This was the actual vulnerable pattern in dnsChanger.";

const RECOMMENDATION = `Apply the same safe settings everywhere you create a BrowserWindow. Managing webPreferences through one shared factory prevents any single window from being missed.

function createSecureWindow(opts) {
  return new BrowserWindow({
    ...opts,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      ...opts.webPreferences,
    },
  });
}`;

// Cross-window inconsistency is inherently project-wide (windows can live in
// different files), so this is an AggregateRule. It fires ONLY when a
// dangerous window coexists with a clearly-safe one — the inconsistency
// itself is the finding. If every window is equally dangerous, EA001/EA002
// already flag each, so EA006 stays silent to avoid piling on. If every
// window is safe, there's nothing to report.
export const EA006: AggregateRule = {
  id: 'EA006',
  kind: 'aggregate',
  severity: 'high',
  target: 'Inconsistent webPreferences across windows (a safe window alongside an unsafe one)',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const allWindows = context.parsedFiles.flatMap((pf) => getWindowCallSites(pf.ast, pf.file.path));
    if (allWindows.length < 2) {
      return [];
    }

    const dangerous = allWindows.filter(isDangerousWindow);
    const hasClearlySafe = allWindows.some(isClearlySafeWindow);
    if (dangerous.length === 0 || !hasClearlySafe) {
      return [];
    }

    // One finding per dangerous window — each is a distinct fix site — noting
    // that a safely-configured window elsewhere proves the inconsistency.
    return dangerous.map((site) => ({
      ruleId: 'EA006',
      severity: 'high',
      confidence: 'high',
      file: site.file,
      line: site.line,
      target: 'This window is configured dangerously, while another window in the same project is configured safely',
      whyDangerous: WHY_DANGEROUS,
      recommendation: RECOMMENDATION,
    }));
  },
};
