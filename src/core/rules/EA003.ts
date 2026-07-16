import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';
import { classifyMissingSecureDefault } from './shared/webPreferencesAbsence.js';

// sandbox's secure default (true) took effect in Electron 20.
const SANDBOX_SAFE_SINCE = 20;

const WHY_DANGEROUS =
  'sandbox가 꺼지면 렌더러 프로세스가 OS 샌드박스 밖에서 실행되어, 렌더러가 침해됐을 때 공격자가 Node 및 시스템 ' +
  '리소스에 훨씬 쉽게 접근합니다. 샌드박스는 렌더러 침해의 피해를 가두는 핵심 방어선입니다.';

const RECOMMENDATION = `sandbox를 켜세요(기본값 유지). preload는 sandbox 호환 API만 사용하도록 작성합니다.

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
          target: 'sandbox: <변수/표현식>',
          whyDangerous: `${WHY_DANGEROUS} (값이 변수/표현식이라 실행 시점에 꺼질 수 있습니다.)`,
        });
      } else if (state === 'absent') {
        const verdict = classifyMissingSecureDefault(context.project.electronMajorVersion, SANDBOX_SAFE_SINCE);
        if (verdict.report) {
          findings.push({
            ...base,
            confidence: 'heuristic',
            target: 'sandbox 미설정',
            whyDangerous: `${WHY_DANGEROUS} ${verdict.reason}`,
          });
        }
      }
    }

    return findings;
  },
};
