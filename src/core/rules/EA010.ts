import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { hasAnyCspConfigured } from './shared/cspSites.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

const WHY_DANGEROUS =
  '프로젝트의 JS/TS 코드와 HTML <meta>를 모두 살폈지만 Content-Security-Policy 설정을 찾지 못했습니다. CSP가 없으면 ' +
  '렌더러가 로드한 콘텐츠에서 인라인 스크립트·원격 스크립트 실행을 막을 방어선이 사라져 XSS의 피해가 그대로 확대됩니다.';

// The scope caveat is part of the finding message, not just docs. HTML <meta>
// CSP is now checked too (shallow regex), so the remaining blind spots are
// narrower — a CSP assembled dynamically, or set by non-standard means — but
// they still exist, so this stays heuristic rather than a certainty claim.
const SCOPE_NOTE =
  '(한계: <meta> CSP는 얕은 정규식으로만 봅니다. 동적으로 조립하거나 비표준 방식으로 설정한 CSP는 놓칠 수 있어 ' +
  'heuristic으로 보고합니다.)';

const RECOMMENDATION = `메인 프로세스에서 응답 헤더로 CSP를 설정하거나, 렌더러 HTML에 <meta>로 설정하세요.

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
  target: 'Content-Security-Policy 설정이 없음 (JS/TS·HTML <meta> 모두)',
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
        target: 'JS/TS·HTML <meta> 어디에도 Content-Security-Policy 설정이 없음',
        whyDangerous: `${WHY_DANGEROUS} ${SCOPE_NOTE}`,
        recommendation: RECOMMENDATION,
      },
    ];
  },
};
