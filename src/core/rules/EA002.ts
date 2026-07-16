import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { classifyMissingSecureDefault } from './shared/webPreferencesAbsence.js';

// contextIsolation's secure default (true) took effect in Electron 12.
const CONTEXT_ISOLATION_SAFE_SINCE = 12;

const WHY_DANGEROUS =
  'contextIsolation이 꺼져 있으면 preload 스크립트와 렌더러 페이지가 같은 JS 컨텍스트를 공유합니다. 페이지의 ' +
  '악성 스크립트가 preload가 노출한 객체나 Electron 내부 API를 프로토타입 오염 등으로 탈취해 권한을 확대할 수 있습니다.';

const RECOMMENDATION = `contextIsolation을 켜고(기본값 유지) preload에서는 contextBridge로만 API를 노출하세요.

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
          target: 'contextIsolation: <변수/표현식>',
          whyDangerous: `${WHY_DANGEROUS} (값이 변수/표현식이라 실행 시점에 꺼질 수 있습니다.)`,
        });
      } else if (state === 'absent') {
        const verdict = classifyMissingSecureDefault(context.project.electronMajorVersion, CONTEXT_ISOLATION_SAFE_SINCE);
        if (verdict.report) {
          findings.push({
            ...base,
            confidence: 'heuristic',
            target: 'contextIsolation 미설정',
            whyDangerous: `${WHY_DANGEROUS} ${verdict.reason}`,
          });
        }
      }
    }

    return findings;
  },
};
