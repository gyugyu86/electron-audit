import traverse from '@babel/traverse';
import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { isStaticSafeLiteral } from '../ast/isStaticSafeLiteral.js';
import { resolveStaticStringValue } from '../ast/resolveStaticString.js';
import { parseUrl } from '../url.js';
import { collectImportBindings } from './shared/importBindings.js';
import { isShellOpenExternalCallee } from './shared/externalInteraction.js';

// http/https/mailto are the schemes it's reasonable to hand to the OS
// browser/mail client. file:, javascript:, data: etc. can execute or expose
// local resources and must never come from an unvalidated source.
const SAFE_SCHEMES = new Set(['https', 'http', 'mailto']);

const WHY_DYNAMIC =
  'shell.openExternal에 정적으로 확정할 수 없는 값이 전달됩니다. 스킴 화이트리스트 없이 임의 URL이 열리면 ' +
  'file://(로컬 파일 접근)이나 javascript:/data:(코드 실행) 같은 위험한 스킴이 외부 입력으로 주입될 수 있습니다.';

const WHY_UNSAFE_LITERAL =
  'shell.openExternal에 안전하지 않은 스킴(file:/javascript:/data: 등)의 URL이 전달됩니다. 이런 스킴은 로컬 ' +
  '리소스 접근이나 코드 실행으로 이어질 수 있어 외부 브라우저로 넘길 대상이 아닙니다.';

const RECOMMENDATION = `열기 전에 스킴을 https/http(필요 시 mailto)로 화이트리스트 검증하세요.

// 취약
shell.openExternal(url);

// 수정 — 안전한 스킴만 통과
function openSafely(url) {
  const { protocol } = new URL(url);
  if (protocol === 'https:' || protocol === 'http:') {
    shell.openExternal(url);
  }
}`;

export const EA040: NodeRule = {
  id: 'EA040',
  kind: 'node',
  severity: 'high',
  target: 'shell.openExternal(<검증되지 않은/위험한 스킴 URL>)',
  whyDangerous: WHY_DYNAMIC,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];
    const imports = collectImportBindings(context.ast);

    traverse(context.ast, {
      CallExpression(path) {
        if (!isShellOpenExternalCallee(path.node.callee, imports)) {
          return;
        }
        const arg = path.node.arguments[0];
        if (!arg) {
          return;
        }
        const line = path.node.loc?.start.line ?? 0;

        // isStaticSafeLiteral is the shared C-group primitive, reused as-is
        // for the dynamic-vs-static decision.
        if (isStaticSafeLiteral(arg, path)) {
          const value = resolveStaticStringValue(arg, path);
          const scheme = value !== undefined ? parseUrl(value).scheme : undefined;
          if (value !== undefined && (scheme === undefined || !SAFE_SCHEMES.has(scheme))) {
            findings.push({
              ruleId: 'EA040',
              severity: 'high',
              confidence: 'high',
              file: context.file.path,
              line,
              target: `shell.openExternal(${JSON.stringify(value)})`,
              whyDangerous: WHY_UNSAFE_LITERAL,
              recommendation: RECOMMENDATION,
            });
          }
          return; // safe scheme literal → silence
        }

        findings.push({
          ruleId: 'EA040',
          severity: 'high',
          confidence: 'heuristic',
          file: context.file.path,
          line,
          target: 'shell.openExternal(<변수/표현식>)',
          whyDangerous: WHY_DYNAMIC,
          recommendation: RECOMMENDATION,
        });
      },
    });

    return findings;
  },
};
