import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

const WHY_DANGEROUS =
  'webSecurity: false는 동일 출처 정책(SOP)을 끄고 원격 리소스를 무분별하게 로드/실행하도록 허용합니다. XSS와 ' +
  '데이터 유출 방어가 통째로 사라집니다.';

const RECOMMENDATION = `webSecurity를 끄지 마세요(기본값 true 유지). 개발 중 CORS 회피가 필요하면 그 목적에 맞는 별도 수단을 쓰세요.

// 취약
new BrowserWindow({ webPreferences: { webSecurity: false } });

// 수정
new BrowserWindow({ webPreferences: { /* webSecurity 기본값 true 유지 */ } });`;

export const EA004: NodeRule = {
  id: 'EA004',
  kind: 'node',
  severity: 'high',
  target: 'BrowserWindow webPreferences.webSecurity',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    // webSecurity defaults to true regardless of version, so 'absent' is
    // safe — only an explicit false (or a dynamic value that could be false)
    // is a finding.
    for (const site of getWindowCallSites(context.ast, context.file.path)) {
      const state = site.webPreferences.webSecurity.state;
      const base = { ruleId: 'EA004', severity: 'high', file: site.file, line: site.line, recommendation: RECOMMENDATION } as const;

      if (state === 'explicit-false') {
        findings.push({ ...base, confidence: 'high', target: 'webSecurity: false', whyDangerous: WHY_DANGEROUS });
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          confidence: 'heuristic',
          target: 'webSecurity: <변수/표현식>',
          whyDangerous: `${WHY_DANGEROUS} (값이 변수/표현식이라 실행 시점에 꺼질 수 있습니다.)`,
        });
      }
    }

    return findings;
  },
};
