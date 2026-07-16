import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';
import { resolveConstIdentifier } from '../../ast/constFolding.js';
import { requireSource, type ImportBinding } from './importBindings.js';

// 'spawn-shell-dynamic' is spawn(cmd, { shell: <not statically true/false> })
// — the sink's very existence is uncertain (shell mode may or may not be
// active at runtime), which is a different kind of uncertainty than the
// argument being unresolved.
export type CommandSinkKind = 'exec' | 'sudo-exec' | 'spawn-shell' | 'spawn-shell-dynamic';

export interface CommandSink {
  kind: CommandSinkKind;
  // The command-string argument (arguments[0]) that this sink runs.
  argNode: t.Node | undefined;
}

const SUDO_PACKAGE_SOURCES = new Set(['sudo-prompt', '@vscode/sudo-prompt', '@expo/sudo-prompt', 'sudo']);

// Pure predicate shared by the C group (EA020/021/022 command injection) and
// the F group (EA050 untrusted-flow): does this call invoke a shell-command
// sink, and if so, which kind and what's its command-string argument? Having
// both groups agree on exactly what counts as a command sink is the point —
// this is the third shared AST primitive after isStaticSafeLiteral and
// resolveStaticStringValue. It MUST stay behavior-identical for the C group
// (a corpus snapshot guards that).
export function isCommandSink(
  call: t.CallExpression,
  imports: Map<string, ImportBinding>,
  path: NodePath,
): CommandSink | null {
  const kind = classifySink(call, imports, path);
  return kind ? { kind, argNode: call.arguments[0] } : null;
}

function classifySink(call: t.CallExpression, imports: Map<string, ImportBinding>, path: NodePath): CommandSinkKind | undefined {
  const callee = call.callee;

  if (t.isIdentifier(callee)) {
    const binding = imports.get(callee.name);
    return binding ? classifyBySourceAndMember(binding.source, binding.importedName, call, path) : undefined;
  }

  if (t.isMemberExpression(callee) && !callee.computed && t.isIdentifier(callee.property) && !t.isSuper(callee.object)) {
    const source = resolveMemberObjectSource(callee.object, imports);
    return source ? classifyBySourceAndMember(source, callee.property.name, call, path) : undefined;
  }

  return undefined;
}

function classifyBySourceAndMember(
  source: string,
  member: string,
  call: t.CallExpression,
  path: NodePath,
): CommandSinkKind | undefined {
  if (source === 'child_process') {
    if (member === 'exec' || member === 'execSync') {
      return 'exec';
    }
    if (member === 'spawn') {
      const shellState = classifySpawnShellState(call, path);
      if (shellState === 'static-true') return 'spawn-shell';
      if (shellState === 'dynamic') return 'spawn-shell-dynamic';
      return undefined; // static-false-or-absent: the safe path, not a sink
    }
    return undefined;
  }
  if (SUDO_PACKAGE_SOURCES.has(source) && member === 'exec') {
    return 'sudo-exec';
  }
  return undefined;
}

function resolveMemberObjectSource(objectNode: t.Expression, imports: Map<string, ImportBinding>): string | undefined {
  if (t.isIdentifier(objectNode)) {
    return imports.get(objectNode.name)?.source;
  }
  // Inline `require('child_process').exec(...)`, never bound to a variable.
  return requireSource(objectNode);
}

type ShellState = 'static-true' | 'static-false-or-absent' | 'dynamic';

// spawn(cmd, args?, options?) — options is whichever argument is an
// ObjectExpression with a `shell` key. A boolean literal (or a same-file
// const that folds to one) settles it statically; anything else means we
// can't know if shell mode is even active at runtime.
function classifySpawnShellState(call: t.CallExpression, path: NodePath): ShellState {
  for (const arg of call.arguments) {
    if (!t.isObjectExpression(arg)) {
      continue;
    }
    const shellProp = arg.properties.find(
      (prop): prop is t.ObjectProperty =>
        t.isObjectProperty(prop) && !prop.computed && t.isIdentifier(prop.key) && prop.key.name === 'shell',
    );
    if (!shellProp) {
      continue;
    }

    const literal = t.isIdentifier(shellProp.value) ? resolveConstIdentifier(shellProp.value.name, path) : shellProp.value;
    if (literal && t.isBooleanLiteral(literal)) {
      return literal.value ? 'static-true' : 'static-false-or-absent';
    }
    return 'dynamic';
  }
  return 'static-false-or-absent';
}
