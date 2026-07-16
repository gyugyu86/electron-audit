import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCspHeaderSites } from './shared/cspSites.js';
import { tokenizeCsp } from '../csp/cspTokenizer.js';

const WHY_DANGEROUS =
  'CSP에 Cordova/하이브리드 앱에서 쓰이는 `gap:` 스킴이 남아 있습니다. 위험이라기보다, 다른 프로젝트의 CSP를 ' +
  '그대로 붙여넣었을 가능성을 알리는 신호입니다 — 이 앱에 실제로 필요한 값인지 점검하세요.';

const RECOMMENDATION = `Electron 앱에 필요 없는 Cordova 잔재(\`gap:\` 등)를 CSP에서 제거하고, 이 앱에 맞는 소스만 남기세요.`;

// info-level, high-confidence (the token is unambiguously present). Kept
// narrow to a clear Cordova signature (`gap:`) to avoid over-flagging.
export const EA013: NodeRule = {
  id: 'EA013',
  kind: 'node',
  severity: 'info',
  target: 'CSP에 Cordova 잔재(`gap:`) 시그니처',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const site of findCspHeaderSites(context.ast)) {
      for (const value of site.values) {
        for (const directive of tokenizeCsp(value)) {
          if (directive.sources.some((source) => source.toLowerCase().startsWith('gap:'))) {
            findings.push({
              ruleId: 'EA013',
              severity: 'info',
              confidence: 'high',
              file: context.file.path,
              line: site.line,
              target: `${directive.name}에 \`gap:\` (Cordova 잔재)`,
              whyDangerous: WHY_DANGEROUS,
              recommendation: RECOMMENDATION,
            });
          }
        }
      }
    }

    return findings;
  },
};
