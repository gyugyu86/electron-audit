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

      // The sudo check comes BEFORE the risk check, and the order is
      // load-bearing. Privilege escalation and argument shape answer different
      // questions: "how bad is this if real" (severity — a root shell) versus
      // "how sure are we it's real" (confidence — whether the command string is
      // syntactically provable). Those are separate fields on Finding for
      // exactly this reason. Ranking risk first let a confidence judgment
      // delete a severity fact: a sudo call whose argument is a variable fell
      // into the generic EA022 bucket, whose text never mentions privilege
      // escalation at all, so the report lost the most dangerous thing about
      // the call site.
      //
      // This is not a corner case. Real code assembles the command before
      // handing it over — `sudo.exec(cmd, …)` and `sudo.exec(parts.join(' '),
      // …)` are the common idioms, and both classify as heuristic, so the
      // pre-existing fixtures (all inline template literals) were the only
      // shape that ever reached EA021.
      if (sink.kind === 'sudo-exec') {
        sites.push({
          ruleId: 'EA021',
          severity: 'critical',
          confidence: risk === 'heuristic' ? 'heuristic' : 'high',
          file: filePath,
          line,
          target,
        });
        return;
      }

      if (risk === 'heuristic') {
        sites.push({ ruleId: 'EA022', severity: 'high', confidence: 'heuristic', file: filePath, line, target });
        return;
      }

      // risk === 'high-confidence' on a non-sudo sink.
      sites.push({ ruleId: 'EA020', severity: 'critical', confidence: 'high', file: filePath, line, target });
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
