import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCommandInjectionSites } from './shared/commandInjection.js';

const WHY_DANGEROUS =
  '셸 명령에 전달된 값이 정적으로 안전하다고 증명되지 않는 변수입니다. 이 값이 사용자 입력이나 네트워크 ' +
  '응답 등 외부에서 온 것이라면 명령 주입으로 이어질 수 있습니다. 정적 분석만으로는 오염 여부를 확정할 수 ' +
  '없어 휴리스틱으로 보고합니다 — 실제 취약 여부는 값의 출처를 직접 확인하세요.';

const RECOMMENDATION = `이 변수가 셸에 들어가기 전에 반드시 검증하거나, execFile + 인자 배열로 바꿔 셸 파싱 자체를 피하세요.

// 검증 없이 그대로 전달됨
exec(command);

// 수정 — 문자열 조립 없이 인자 배열로 전달 (셸을 거치지 않음)
const { execFile } = require('child_process');
execFile(command, args, callback);`;

export const EA022: NodeRule = {
  id: 'EA022',
  kind: 'node',
  severity: 'high',
  target: 'child_process exec류에 전달된, 정적으로 안전을 증명할 수 없는 변수',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    return findCommandInjectionSites(context.ast, context.file.path, context.file.content)
      .filter((site) => site.ruleId === 'EA022')
      .map((site) => ({ ...site, whyDangerous: WHY_DANGEROUS, recommendation: RECOMMENDATION }));
  },
};
