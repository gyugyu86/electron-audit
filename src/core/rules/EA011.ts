import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { collectCspStrings, findUnsafeCspHits } from './shared/cspSites.js';

const WHY_DANGEROUS =
  "CSP에 'unsafe-inline' 또는 'unsafe-eval'이 있으면 인라인 스크립트/스타일이나 eval 계열 실행이 허용됩니다. " +
  '스크립트 실행 디렉티브(script-src/default-src)의 unsafe-inline·모든 unsafe-eval은 XSS→코드실행 경로라 high로, ' +
  '그 외 디렉티브(style-src 등)의 unsafe-inline은 공격 표면이 제한적이라 medium으로 보고합니다.';

const RECOMMENDATION = `'unsafe-inline'/'unsafe-eval'을 제거하고, 필요한 인라인은 nonce나 hash로 개별 허용하세요.

// 취약
"script-src 'self' 'unsafe-inline' 'unsafe-eval'"

// 수정
"script-src 'self' 'nonce-<요청마다 생성한 값>'"`;

// Aggregate (not per-file): the CSP surface now spans JS response-header sites
// AND HTML <meta> tags, so it's judged project-wide from the unified
// collectCspStrings list. Token-based, never a raw substring scan: a host or
// comment that happens to contain "unsafe-inline" must not trigger this —
// only an exact source token does. Severity is directive-graded (see
// findUnsafeCspHits) so declared severity here is the max the rule can emit.
export const EA011: AggregateRule = {
  id: 'EA011',
  kind: 'aggregate',
  severity: 'high',
  target: "CSP 'unsafe-inline' / 'unsafe-eval'",
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const csp of collectCspStrings(context)) {
      for (const hit of findUnsafeCspHits(csp.value)) {
        findings.push({
          ruleId: 'EA011',
          severity: hit.severity,
          confidence: 'high',
          file: csp.file,
          line: csp.line,
          target: `${hit.directive}에 ${hit.keywords.join(', ')}`,
          whyDangerous: WHY_DANGEROUS,
          recommendation: RECOMMENDATION,
        });
      }
    }

    return findings;
  },
};
