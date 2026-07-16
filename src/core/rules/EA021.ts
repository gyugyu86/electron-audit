import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCommandInjectionSites } from './shared/commandInjection.js';

const WHY_DANGEROUS =
  '명령 주입 취약점이 sudo-prompt류 권한상승 래퍼와 결합되면, 주입된 명령이 사용자 승인 절차를 거쳐 그대로 ' +
  '관리자 권한으로 실행됩니다. 렌더러나 네트워크에서 흘러온 값이 여기까지 도달하면 시스템 전체가 장악됩니다.';

const RECOMMENDATION = `권한상승이 필요한 명령은 고정된 화이트리스트만 실행하고, 인자는 검증 후 값만 전달하세요.
sudo-prompt류는 내부적으로 셸을 거치므로 명령 문자열에 외부 입력을 절대 보간하지 마세요.

// 취약
sudo.exec(\`some-tool --target=\${url}\`, options, callback);

// 수정 — 화이트리스트에 있는 고정 명령 + 검증된 인자만
const ALLOWED_TARGETS = new Set(['a', 'b']);
if (!ALLOWED_TARGETS.has(target)) throw new Error('invalid target');
sudo.exec(\`some-tool --target=\${target}\`, options, callback);`;

export const EA021: NodeRule = {
  id: 'EA021',
  kind: 'node',
  severity: 'critical',
  target: 'sudo-prompt류 권한상승 exec에 보간·연결된 명령 문자열',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    return findCommandInjectionSites(context.ast, context.file.path, context.file.content)
      .filter((site) => site.ruleId === 'EA021')
      .map((site) => ({ ...site, whyDangerous: WHY_DANGEROUS, recommendation: RECOMMENDATION }));
  },
};
