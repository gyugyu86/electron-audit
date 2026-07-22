import type { AggregateRule, AggregateRuleContext, Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findSetWindowOpenHandlerCalls } from './shared/windowOpenHandler.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { isClearlySafeWindow } from './shared/windowSafety.js';

const WHY_UNCONDITIONAL =
  'setWindowOpenHandler unconditionally allows (action: "allow") every window-creation request. An arbitrary URL ' +
  'can be opened in a new window via window.open or a target=_blank link, turning it into a channel for untrusted ' +
  'content to spawn windows inside the app.';

const WHY_ABSENT =
  "A project whose windows aren't otherwise locked down has no setWindowOpenHandler at all. With nothing " +
  'controlling new-window requests, an arbitrary URL could be opened via window.open and similar APIs. (Reported ' +
  "as heuristic since we can't statically confirm whether a real window-opening code path even exists.)";

const RECOMMENDATION = `Attach setWindowOpenHandler to every window, and only allow a URL to open after explicitly validating it.

win.webContents.setWindowOpenHandler(({ url }) => {
  if (isAllowed(url)) {
    return { action: 'allow' };
  }
  return { action: 'deny' };
});`;

// Facet 1 (NodeRule): a handler that exists but rubber-stamps every request.
export const EA041UnconditionalAllow: NodeRule = {
  id: 'EA041',
  kind: 'node',
  severity: 'medium',
  target: 'setWindowOpenHandler(() => ({ action: "allow" }))',
  whyDangerous: WHY_UNCONDITIONAL,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    return findSetWindowOpenHandlerCalls(context.ast)
      .filter((call) => call.unconditionalAllow)
      .map((call) => ({
        ruleId: 'EA041',
        severity: 'medium',
        confidence: 'high',
        file: context.file.path,
        line: call.line,
        target: 'setWindowOpenHandler(() => ({ action: "allow" }))',
        whyDangerous: WHY_UNCONDITIONAL,
        recommendation: RECOMMENDATION,
      }));
  },
};

// Facet 2 (AggregateRule): no setWindowOpenHandler anywhere in the project.
// This is a genuine project-wide absence, so it must be an AggregateRule.
// Gated three ways to stay off false positives: (1) at least one
// BrowserWindow must exist, (2) no handler may exist anywhere, and (3) at
// least one window must NOT be clearly safe — a fully locked-down app
// (contextIsolation on / nodeIntegration off, like electron/minimal-repro)
// missing a handler is low risk and reporting it would be noise. The anchor
// is that first not-clearly-safe window.
export const EA041Absence: AggregateRule = {
  id: 'EA041',
  kind: 'aggregate',
  severity: 'medium',
  target: 'BrowserWindow exists but setWindowOpenHandler is missing anywhere in the project',
  whyDangerous: WHY_ABSENT,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const allWindows = context.parsedFiles.flatMap((pf) => getWindowCallSites(pf.ast, pf.file.path));
    if (allWindows.length === 0) {
      return [];
    }

    const hasHandler = context.parsedFiles.some((pf) => findSetWindowOpenHandlerCalls(pf.ast).length > 0);
    if (hasHandler) {
      return [];
    }

    const anchor = allWindows.find((site) => !isClearlySafeWindow(site));
    if (!anchor) {
      return []; // every window is clearly safe → low risk, stay silent
    }

    return [
      {
        ruleId: 'EA041',
        severity: 'medium',
        confidence: 'heuristic',
        file: anchor.file,
        line: anchor.line,
        target: 'setWindowOpenHandler is missing (a window that is not clearly safe exists)',
        whyDangerous: WHY_ABSENT,
        recommendation: RECOMMENDATION,
      },
    ];
  },
};
