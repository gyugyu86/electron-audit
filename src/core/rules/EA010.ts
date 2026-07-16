import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { hasAnyCspConfigured } from './shared/cspSites.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

const WHY_DANGEROUS =
  "This project's JS/TS code and HTML <meta> were both checked, but no Content-Security-Policy configuration was " +
  'found. Without a CSP, there\'s no defense left against inline or remote script execution in whatever content ' +
  "the renderer loads, so the impact of any XSS is unconstrained.";

// The scope caveat is part of the finding message, not just docs. HTML <meta>
// CSP is now checked too (shallow regex), so the remaining blind spots are
// narrower — a CSP assembled dynamically, or set by non-standard means — but
// they still exist, so this stays heuristic rather than a certainty claim.
const SCOPE_NOTE =
  '(Limit: <meta> CSP is only read via a shallow regex. A CSP assembled dynamically, or set through a ' +
  'non-standard mechanism, can be missed — reported as heuristic for that reason.)';

const RECOMMENDATION = `Set a CSP via a response header in the main process, or via a <meta> tag in the renderer's HTML.

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': ["default-src 'self'"],
    },
  });
});`;

// Project-wide absence → AggregateRule. Gated on at least one BrowserWindow
// existing (no renderer, no CSP concern — avoids firing on a plain Node
// project) AND no CSP header being set anywhere in JS. Always heuristic
// because of the HTML-<meta> blind spot above. Anchored at the first window.
export const EA010: AggregateRule = {
  id: 'EA010',
  kind: 'aggregate',
  severity: 'high',
  target: 'No Content-Security-Policy configuration (checked both JS/TS and HTML <meta>)',
  whyDangerous: `${WHY_DANGEROUS} ${SCOPE_NOTE}`,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const windows = context.parsedFiles.flatMap((pf) => getWindowCallSites(pf.ast, pf.file.path));
    if (windows.length === 0) {
      return [];
    }

    // Now that HTML <meta> CSP is checked too, this only fires when NEITHER
    // JS nor HTML configures a CSP anywhere — a stronger absence claim than
    // before (previously it fired even when a <meta> CSP existed but was
    // invisible to a JS-only scan).
    if (hasAnyCspConfigured(context)) {
      return [];
    }

    const [anchor] = windows;
    if (!anchor) {
      return [];
    }
    return [
      {
        ruleId: 'EA010',
        severity: 'high',
        confidence: 'heuristic',
        file: anchor.file,
        line: anchor.line,
        target: 'No Content-Security-Policy configuration anywhere in JS/TS or HTML <meta>',
        whyDangerous: `${WHY_DANGEROUS} ${SCOPE_NOTE}`,
        recommendation: RECOMMENDATION,
      },
    ];
  },
};
