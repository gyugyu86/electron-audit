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
  "A value that can't be statically determined is passed to shell.openExternal. Without a scheme allowlist, an " +
  'arbitrary URL could be opened, letting a dangerous scheme — file: (local file access) or javascript:/data: ' +
  '(code execution) — be injected via external input.';

const WHY_UNSAFE_LITERAL =
  'A URL with an unsafe scheme (file:/javascript:/data:, etc.) is passed to shell.openExternal. These schemes can ' +
  "lead to local resource access or code execution, and shouldn't be handed to an external browser.";

const RECOMMENDATION = `Allowlist the scheme to https/http (and mailto if needed) before opening.

// vulnerable
shell.openExternal(url);

// fixed — only a safe scheme gets through
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
  target: 'shell.openExternal(<unvalidated URL / unsafe scheme>)',
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
          target: 'shell.openExternal(<variable/expression>)',
          whyDangerous: WHY_DYNAMIC,
          recommendation: RECOMMENDATION,
        });
      },
    });

    return findings;
  },
};
