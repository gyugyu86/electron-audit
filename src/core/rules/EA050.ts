import traverse from '@babel/traverse';
import type { NodePath } from '@babel/traverse';
import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { collectImportBindings } from './shared/importBindings.js';
import { isCommandSink } from './shared/commandSink.js';
import { isShellOpenExternalCallee, isLoadUrlCallee } from './shared/externalInteraction.js';
import { fsPathSinkArg, isTaintedValue, type SourceFamily } from './shared/untrustedFlow.js';
import type * as t from '@babel/types';

// Staged source families (see untrustedFlow.ts). Verified against the clean
// corpus one family at a time to isolate any false positive by family.
const SOURCE_FAMILIES = new Set<SourceFamily>(['B', 'A', 'C']);

type SinkBucket = 'command' | 'external-url' | 'fs-path';

interface SinkMessage {
  target: string;
  whyDangerous: string;
  recommendation: string;
}

// EA050 is redefined away from "remote data" — statically we cannot prove a
// value is remote. It is: untrusted deserialization / external input reaching
// a dangerous sink without validation. The advice is "validate/allowlist
// before the sink", correct whether the value is local or remote. The FP
// worry about JSON.parse thus becomes a legitimate heuristic warning, not a
// false positive. Always confidence 'heuristic'; the sink kind (which the
// fix differs by) is spelled out per bucket.
const MESSAGES: Record<SinkBucket, SinkMessage> = {
  command: {
    target: 'Deserialized untrusted data (possibly remote) reaches a shell command unvalidated',
    whyDangerous:
      "A value deserialized via JSON.parse or similar — one that can't be statically guaranteed trustworthy " +
      '(it could be a remote response) — reaches a shell command unvalidated. If this value is attacker-controlled, ' +
      'it leads to command injection.',
    recommendation: `Validate or allowlist the value before it reaches the sink, and use execFile + an argument array instead of a shell.

const ALLOWED = new Set(['a', 'b']);
if (!ALLOWED.has(info.action)) throw new Error('invalid');
execFile('tool', ['--action', info.action]);`,
  },
  'external-url': {
    target: 'Deserialized untrusted data (possibly remote) reaches an external URL open/load unvalidated',
    whyDangerous:
      "A deserialized value that can't be guaranteed trustworthy reaches shell.openExternal / loadURL unvalidated. " +
      'An arbitrary scheme (file:/javascript:) or origin could be opened.',
    recommendation: `Allowlist the scheme and origin before opening/loading.

const { protocol, host } = new URL(info.url);
if (protocol === 'https:' && ALLOWED_HOSTS.has(host)) shell.openExternal(info.url);`,
  },
  'fs-path': {
    target: 'Deserialized untrusted data (possibly remote) reaches a file path unvalidated',
    whyDangerous:
      "A deserialized value that can't be guaranteed trustworthy is used as a file path unvalidated. Path " +
      'traversal could let it read or overwrite a file outside the intended base directory.',
    recommendation: `Normalize the path, confirm it stays inside the allowed base directory, and reject it if it escapes.

const resolved = path.resolve(BASE_DIR, info.path);
if (!resolved.startsWith(BASE_DIR + path.sep)) throw new Error('path escape');
fs.readFile(resolved, cb);`,
  },
};

export const EA050: NodeRule = {
  id: 'EA050',
  kind: 'node',
  severity: 'medium',
  target: 'Untrusted deserialized/external input reaches a dangerous sink without validation',
  whyDangerous: MESSAGES.command.whyDangerous,
  recommendation: MESSAGES.command.recommendation,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];
    const imports = collectImportBindings(context.ast);

    traverse(context.ast, {
      CallExpression(path) {
        const sink = resolveSink(path, imports);
        if (!sink || !sink.argNode) {
          return;
        }
        if (!isTaintedValue(sink.argNode, path, imports, SOURCE_FAMILIES)) {
          return;
        }

        const message = MESSAGES[sink.bucket];
        findings.push({
          ruleId: 'EA050',
          severity: 'medium',
          confidence: 'heuristic',
          file: context.file.path,
          line: path.node.loc?.start.line ?? 0,
          target: message.target,
          whyDangerous: message.whyDangerous,
          recommendation: message.recommendation,
        });
      },
    });

    return findings;
  },
};

function resolveSink(
  path: NodePath<t.CallExpression>,
  imports: ReturnType<typeof collectImportBindings>,
): { bucket: SinkBucket; argNode: t.Node | undefined } | undefined {
  const command = isCommandSink(path.node, imports, path);
  if (command) {
    return { bucket: 'command', argNode: command.argNode };
  }

  const callee = path.node.callee;
  if (isShellOpenExternalCallee(callee, imports) || isLoadUrlCallee(callee)) {
    return { bucket: 'external-url', argNode: path.node.arguments[0] };
  }

  const fsArg = fsPathSinkArg(path.node, imports);
  if (fsArg !== undefined) {
    return { bucket: 'fs-path', argNode: fsArg };
  }

  return undefined;
}
