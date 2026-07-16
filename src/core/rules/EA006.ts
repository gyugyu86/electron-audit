import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { isClearlySafeWindow, isDangerousWindow } from './shared/windowSafety.js';

const WHY_DANGEROUS =
  '같은 프로젝트 안에서 어떤 창은 안전하게(contextIsolation on / nodeIntegration off) 설정됐는데 다른 창은 ' +
  '위험하게 설정돼 있습니다. 보통 메인 창만 신경 쓰고 자식 창(예: open-win 류)의 webPreferences를 빠뜨린 실수로, ' +
  '공격자는 방어가 약한 창을 노립니다. dnsChanger의 실제 취약 패턴이 이것이었습니다.';

const RECOMMENDATION = `모든 BrowserWindow 생성 지점에 동일한 안전 설정을 적용하세요. 공용 팩토리로 webPreferences를 한 곳에서 관리하면 창마다 빠뜨리는 실수를 막을 수 있습니다.

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
  target: '창 간 webPreferences 불일치 (안전한 창과 위험한 창 혼재)',
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
      target: '이 창은 위험하게 설정됐으나 같은 프로젝트의 다른 창은 안전하게 설정됨',
      whyDangerous: WHY_DANGEROUS,
      recommendation: RECOMMENDATION,
    }));
  },
};
