import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';
import { collectCspStrings, findWildcardCspDirectives } from './shared/cspSites.js';

const WHY_DANGEROUS =
  'CSP 디렉티브의 소스가 와일드카드 `*` 하나면 모든 오리진을 허용하는 것과 같아 CSP가 사실상 없는 것과 다르지 ' +
  '않습니다. 임의의 원격 스크립트/리소스가 로드될 수 있습니다.';

const RECOMMENDATION = `\`*\` 대신 실제로 필요한 오리진만 명시하세요. 서브도메인이 필요하면 \`*.example.com\`처럼 도메인을 고정하세요.

// 취약
"default-src *"

// 수정
"default-src 'self' https://api.example.com"`;

// Aggregate: judges the unified CSP surface (JS response headers + HTML
// <meta>). Exact-token match ONLY — a source token of exactly "*" allows every
// origin and is a finding; a partial wildcard like "*.foo.com" or
// "https://*.cdn.com" restricts to one domain's subdomains and is NOT — the
// whole reason CSP judgments tokenize first instead of running a `*` regex
// over the raw string.
export const EA012: AggregateRule = {
  id: 'EA012',
  kind: 'aggregate',
  severity: 'medium',
  target: 'CSP 소스가 와일드카드 `*` (모든 오리진 허용)',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const csp of collectCspStrings(context)) {
      for (const directive of findWildcardCspDirectives(csp.value)) {
        findings.push({
          ruleId: 'EA012',
          severity: 'medium',
          confidence: 'high',
          file: csp.file,
          line: csp.line,
          target: `${directive}에 와일드카드 \`*\``,
          whyDangerous: WHY_DANGEROUS,
          recommendation: RECOMMENDATION,
        });
      }
    }

    return findings;
  },
};
