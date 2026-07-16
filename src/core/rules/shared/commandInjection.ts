import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';
import type { File } from '@babel/types';
import type { Confidence, Severity } from '../../types.js';
import { isStaticSafeLiteral } from '../../ast/isStaticSafeLiteral.js';
import { collectImportBindings } from './importBindings.js';
import { isCommandSink } from './commandSink.js';

export interface CommandInjectionSite {
  ruleId: 'EA020' | 'EA021' | 'EA022';
  severity: Severity;
  confidence: Confidence;
  file: string;
  line: number;
  target: string;
}

const TARGET_SNIPPET_MAX_LENGTH = 160;

type ArgumentRisk = 'safe' | 'high-confidence' | 'heuristic';

// EA020/EA021/EA022 are three severities of ONE classification (a call site
// produces at most one finding, never more than one ruleId) — this walks
// each file once and tags every finding with its ruleId; EA020.ts/EA021.ts/
// EA022.ts each just filter to their own ruleId and attach their own
// whyDangerous/recommendation text. Memoized per-AST since all three rule
// files call this for the same file within one RuleEngine run.
//
// Command-sink detection is now the shared isCommandSink primitive (also
// used by EA050); this module owns only the *argument risk* classification,
// which is C-group-specific (syntactic injection shape).
const cache = new WeakMap<File, CommandInjectionSite[]>();

export function findCommandInjectionSites(ast: File, filePath: string, fileContent: string): CommandInjectionSite[] {
  const cached = cache.get(ast);
  if (cached) {
    return cached;
  }

  const imports = collectImportBindings(ast);
  const sites: CommandInjectionSite[] = [];

  traverse(ast, {
    CallExpression(path) {
      const sink = isCommandSink(path.node, imports, path);
      if (!sink) {
        return;
      }

      const risk = classifyArgumentRisk(sink.argNode, path);
      if (risk === 'safe') {
        return;
      }

      const line = path.node.loc?.start.line ?? 0;
      const target = extractSourceSnippet(fileContent, path.node);

      // Sink existence itself is uncertain here (shell may or may not be
      // active at runtime) — a risky cmd (either shape) downgrades all the
      // way to EA022 rather than the EA020 it'd get with a confirmed sink.
      if (sink.kind === 'spawn-shell-dynamic') {
        sites.push({ ruleId: 'EA022', severity: 'high', confidence: 'heuristic', file: filePath, line, target });
        return;
      }

      if (risk === 'heuristic') {
        sites.push({ ruleId: 'EA022', severity: 'high', confidence: 'heuristic', file: filePath, line, target });
        return;
      }

      // risk === 'high-confidence': only escalate to EA021 when the sink is
      // confidently resolved to a whitelisted sudo wrapper; an unresolved
      // sink identity stays EA020 (escalation only when confident).
      if (sink.kind === 'sudo-exec') {
        sites.push({ ruleId: 'EA021', severity: 'critical', confidence: 'high', file: filePath, line, target });
      } else {
        sites.push({ ruleId: 'EA020', severity: 'critical', confidence: 'high', file: filePath, line, target });
      }
    },
  });

  cache.set(ast, sites);
  return sites;
}

function classifyArgumentRisk(arg: t.Node | null | undefined, path: NodePath): ArgumentRisk {
  if (!arg) {
    return 'safe';
  }

  if (t.isStringLiteral(arg)) {
    return 'safe';
  }

  if (t.isTemplateLiteral(arg)) {
    const allInterpolationsSafe = arg.expressions.every((expr) => isStaticSafeLiteral(expr, path));
    return allInterpolationsSafe ? 'safe' : 'high-confidence';
  }

  if (t.isBinaryExpression(arg) && arg.operator === '+') {
    return isStaticSafeLiteral(arg, path) ? 'safe' : 'high-confidence';
  }

  if (t.isIdentifier(arg)) {
    return isStaticSafeLiteral(arg, path) ? 'safe' : 'heuristic';
  }

  // Anything else passed directly (call expression, member expression,
  // conditional, ...) isn't one of the syntactically-obvious injection
  // shapes above, but it's also not provably safe — heuristic, not silent
  // and not critical, since we can't structurally justify either extreme.
  return 'heuristic';
}

function extractSourceSnippet(content: string, node: t.Node): string {
  if (node.start == null || node.end == null) {
    return '<call site>';
  }
  const collapsed = content.slice(node.start, node.end).replace(/\s+/g, ' ').trim();
  return collapsed.length > TARGET_SNIPPET_MAX_LENGTH
    ? `${collapsed.slice(0, TARGET_SNIPPET_MAX_LENGTH - 3)}...`
    : collapsed;
}
