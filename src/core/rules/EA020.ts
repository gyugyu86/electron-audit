import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCommandInjectionSites } from './shared/commandInjection.js';

const WHY_DANGEROUS =
  '셸 명령 문자열에 외부 영향을 받을 수 있는 값을 템플릿 보간이나 문자열 연결로 직접 끼워 넣으면, ' +
  '공격자가 세미콜론·백틱 등 셸 메타문자를 주입해 의도하지 않은 명령을 함께 실행시킬 수 있습니다(명령 주입).';

const RECOMMENDATION = `exec/execSync 대신 execFile(또는 shell:false spawn)에 인자를 배열로 넘겨, 값이 셸 파싱을 거치지 않게 하세요.

// 취약
const { exec } = require('child_process');
exec(\`kill \${pid}\`);

// 수정 — 인자를 배열로 분리, 셸을 거치지 않음
const { execFile } = require('child_process');
execFile('kill', [String(pid)]);`;

export const EA020: NodeRule = {
  id: 'EA020',
  kind: 'node',
  severity: 'critical',
  target: 'child_process exec/execSync (또는 spawn shell:true)에 보간·연결된 명령 문자열',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    return findCommandInjectionSites(context.ast, context.file.path, context.file.content)
      .filter((site) => site.ruleId === 'EA020')
      .map((site) => ({ ...site, whyDangerous: WHY_DANGEROUS, recommendation: RECOMMENDATION }));
  },
};
