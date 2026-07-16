import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

const WHY_DANGEROUS =
  'allowRunningInsecureContent: true는 https 페이지가 http로 된 스크립트 등 혼합(mixed) 콘텐츠를 실행하도록 ' +
  '허용합니다. 중간자 공격자가 http 리소스를 바꿔치기해 페이지에서 임의 코드를 실행할 수 있습니다.';

const RECOMMENDATION = `allowRunningInsecureContent를 켜지 마세요(기본값 false 유지). 모든 리소스를 https로 제공하세요.

// 취약
new BrowserWindow({ webPreferences: { allowRunningInsecureContent: true } });

// 수정
new BrowserWindow({ webPreferences: { /* allowRunningInsecureContent 기본값 false 유지 */ } });`;

export const EA005: NodeRule = {
  id: 'EA005',
  kind: 'node',
  severity: 'medium',
  target: 'BrowserWindow webPreferences.allowRunningInsecureContent',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    // This one defaults to false, so the danger is an explicit TRUE (or a
    // dynamic value that could be true), not an absence.
    for (const site of getWindowCallSites(context.ast, context.file.path)) {
      const state = site.webPreferences.allowRunningInsecureContent.state;
      const base = { ruleId: 'EA005', severity: 'medium', file: site.file, line: site.line, recommendation: RECOMMENDATION } as const;

      if (state === 'explicit-true') {
        findings.push({ ...base, confidence: 'high', target: 'allowRunningInsecureContent: true', whyDangerous: WHY_DANGEROUS });
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          confidence: 'heuristic',
          target: 'allowRunningInsecureContent: <변수/표현식>',
          whyDangerous: `${WHY_DANGEROUS} (값이 변수/표현식이라 실행 시점에 켜질 수 있습니다.)`,
        });
      }
    }

    return findings;
  },
};
