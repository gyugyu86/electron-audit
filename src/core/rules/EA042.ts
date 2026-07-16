import traverse from '@babel/traverse';
import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { resolveStaticStringValue } from '../ast/resolveStaticString.js';
import { isLocalhostHost, parseUrl } from '../url.js';
import { isLoadUrlCallee } from './shared/externalInteraction.js';

// Scope note: EA042 judges LITERAL URLs only. A variable/expression URL is
// left to F-group EA050 (dataflow) so E stays a shallow, syntactic pass and
// doesn't double-cover dataflow territory.
const RECOMMENDATION = `가능하면 로컬 콘텐츠는 loadFile로 로드하고, 원격을 로드해야 한다면 https로 고정된 신뢰 도메인만 사용하세요.

// 취약: 원격/비-https 콘텐츠 로드
win.loadURL('http://example.com/app');

// 수정: 로컬 파일 로드
win.loadFile('index.html');`;

export const EA042: NodeRule = {
  id: 'EA042',
  kind: 'node',
  severity: 'medium',
  target: 'loadURL(<원격 URL 또는 http 비-https>)',
  whyDangerous: '원격 콘텐츠를 창에 로드하면 앱이 통제할 수 없는 코드를 실행하게 됩니다.',
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    traverse(context.ast, {
      CallExpression(path) {
        if (!isLoadUrlCallee(path.node.callee)) {
          return;
        }
        const arg = path.node.arguments[0];
        if (!arg) {
          return;
        }

        const value = resolveStaticStringValue(arg, path);
        if (value === undefined) {
          return; // dynamic → EA050/F group, not EA042
        }

        const { scheme, host } = parseUrl(value);
        if (scheme === 'file' || !host || isLocalhostHost(host)) {
          return; // local file, non-network scheme, or dev localhost → silence
        }

        const insecure = scheme === 'http';
        const whyDangerous = insecure
          ? `loadURL이 원격 콘텐츠를 http(비-https)로 로드합니다(${value}). 원격 코드를 실행하게 될 뿐 아니라 전송 구간이 변조·가로채기에 노출됩니다.`
          : `loadURL이 원격 콘텐츠를 로드합니다(${value}). 앱이 통제할 수 없는 원격 코드가 창에서 실행될 수 있습니다.`;

        findings.push({
          ruleId: 'EA042',
          severity: 'medium',
          confidence: 'high',
          file: context.file.path,
          line: path.node.loc?.start.line ?? 0,
          target: `loadURL(${JSON.stringify(value)})`,
          whyDangerous,
          recommendation: RECOMMENDATION,
        });
      },
    });

    return findings;
  },
};
