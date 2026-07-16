import type { AggregateRule, AggregateRuleContext, Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findSetWindowOpenHandlerCalls } from './shared/windowOpenHandler.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { isClearlySafeWindow } from './shared/windowSafety.js';

const WHY_UNCONDITIONAL =
  'setWindowOpenHandler가 모든 창 생성 요청을 무조건 허용(action: "allow")합니다. window.open이나 target=_blank ' +
  '링크로 임의의 URL이 새 창으로 열릴 수 있어, 신뢰할 수 없는 콘텐츠가 앱 안에서 창을 띄우는 통로가 됩니다.';

const WHY_ABSENT =
  '창을 안전하게 잠그지 않은 프로젝트에 setWindowOpenHandler가 전혀 없습니다. 새 창 생성 요청을 통제하는 지점이 ' +
  '없으면 window.open 등으로 임의 URL이 열릴 수 있습니다. (정적으로 실제 창 열기 경로 유무까지는 확인할 수 없어 휴리스틱으로 보고합니다.)';

const RECOMMENDATION = `모든 창에 setWindowOpenHandler를 걸고, 허용할 URL을 명시적으로 검증한 뒤에만 열도록 하세요.

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
// (contextIsolation on / nodeIntegration off, like electron-quick-start)
// missing a handler is low risk and reporting it would be noise. The anchor
// is that first not-clearly-safe window.
export const EA041Absence: AggregateRule = {
  id: 'EA041',
  kind: 'aggregate',
  severity: 'medium',
  target: 'BrowserWindow가 있으나 setWindowOpenHandler가 프로젝트 어디에도 없음',
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
        target: 'setWindowOpenHandler 부재 (안전하게 설정되지 않은 창이 존재)',
        whyDangerous: WHY_ABSENT,
        recommendation: RECOMMENDATION,
      },
    ];
  },
};
