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
    target: '역직렬화된 신뢰 불가 데이터(원격일 수 있음)가 검증 없이 셸 명령으로 흘러감',
    whyDangerous:
      'JSON.parse 등으로 역직렬화된, 정적으로 신뢰를 보장할 수 없는 값(원격 응답일 수 있음)이 검증 없이 셸 명령에 ' +
      '도달합니다. 이 값이 공격자 통제 하에 있으면 명령 주입으로 이어집니다.',
    recommendation: `싱크에 넘기기 전에 값을 검증하거나 화이트리스트로 제한하고, 셸 대신 execFile + 인자 배열을 쓰세요.

const ALLOWED = new Set(['a', 'b']);
if (!ALLOWED.has(info.action)) throw new Error('invalid');
execFile('tool', ['--action', info.action]);`,
  },
  'external-url': {
    target: '역직렬화된 신뢰 불가 데이터(원격일 수 있음)가 검증 없이 외부 URL 열기/로드로 흘러감',
    whyDangerous:
      '역직렬화된, 신뢰를 보장할 수 없는 값이 검증 없이 shell.openExternal / loadURL에 도달합니다. 임의의 스킴' +
      '(file:/javascript:)이나 오리진이 열릴 수 있습니다.',
    recommendation: `열기/로드 전에 스킴과 오리진을 화이트리스트로 검증하세요.

const { protocol, host } = new URL(info.url);
if (protocol === 'https:' && ALLOWED_HOSTS.has(host)) shell.openExternal(info.url);`,
  },
  'fs-path': {
    target: '역직렬화된 신뢰 불가 데이터(원격일 수 있음)가 검증 없이 파일 경로로 흘러감',
    whyDangerous:
      '역직렬화된, 신뢰를 보장할 수 없는 값이 검증 없이 파일 경로로 쓰입니다. 경로 탐색(path traversal)으로 ' +
      '기준 디렉토리 밖의 파일을 읽거나 덮어쓸 수 있습니다.',
    recommendation: `경로를 정규화한 뒤 허용된 기준 디렉토리 안에 있는지 확인하고, 벗어나면 거부하세요.

const resolved = path.resolve(BASE_DIR, info.path);
if (!resolved.startsWith(BASE_DIR + path.sep)) throw new Error('path escape');
fs.readFile(resolved, cb);`,
  },
};

export const EA050: NodeRule = {
  id: 'EA050',
  kind: 'node',
  severity: 'medium',
  target: '신뢰 불가 역직렬화/외부 입력이 검증 없이 위험 싱크로 직행',
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
