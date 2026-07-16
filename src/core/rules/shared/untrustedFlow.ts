import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';
import type { ImportBinding } from './importBindings.js';
import { requireSource } from './importBindings.js';

// EA050's dataflow approximation. EA050 is deliberately NOT "a remote-data
// rule" — statically we can't prove a value is remote. It's "untrusted
// deserialization / external input reaches a dangerous sink without
// validation", always reported at confidence 'heuristic'.
//
// SOURCES (what counts as untrusted input), added in stages:
//   B — a response-body parse (`.json()` / `.text()`) or an axios call.
//   A — `JSON.parse(x)`, unless x is a same-scope local filesystem read.
//   C — a parameter (after `event`) of an ipcMain.handle/on / ipcRenderer.on
//       handler callback.
//
// FLOW — same FUNCTION scope only (like the C group). Taint propagates through
// member/element access, template/`+` interpolation, and one hop of a
// same-function variable binding. It does NOT cross function boundaries
// (nested callbacks, separate functions), function return values, or
// mutation (`body += chunk`). Those are the accepted false-negatives that
// make this a heuristic — and the reason a same-file `res → body → info`
// chain across https.get callbacks is only caught at the in-scope
// `info = JSON.parse(body)` hop, via source family A.

const FS_MODULE_SOURCES = new Set(['fs', 'node:fs', 'fs/promises', 'node:fs/promises']);
const FS_PATH_METHODS = new Set([
  'readFile',
  'readFileSync',
  'writeFile',
  'writeFileSync',
  'unlink',
  'unlinkSync',
  'appendFile',
  'appendFileSync',
  'createReadStream',
  'createWriteStream',
]);

export type SourceFamily = 'B' | 'A' | 'C';

// ── Taint check ──────────────────────────────────────────────────────────

export function isTaintedValue(
  node: t.Node,
  path: NodePath,
  imports: Map<string, ImportBinding>,
  families: Set<SourceFamily>,
): boolean {
  return checkTaint(node, path, imports, families, new Set());
}

function checkTaint(
  node: t.Node,
  path: NodePath,
  imports: Map<string, ImportBinding>,
  families: Set<SourceFamily>,
  seen: Set<t.Node>,
): boolean {
  if (seen.has(node)) {
    return false;
  }
  seen.add(node);

  const inner = unwrap(node);

  if (isUntrustedSourceExpression(inner, path, imports, families)) {
    return true;
  }

  if (t.isIdentifier(inner)) {
    return identifierIsTainted(inner, path, imports, families, seen);
  }

  if (t.isMemberExpression(inner) && !t.isSuper(inner.object)) {
    return checkTaint(inner.object, path, imports, families, seen);
  }

  if (t.isTemplateLiteral(inner)) {
    return inner.expressions.some((expr) => !t.isTSType(expr) && checkTaint(expr, path, imports, families, seen));
  }

  if (t.isBinaryExpression(inner) && inner.operator === '+' && !t.isPrivateName(inner.left)) {
    return (
      checkTaint(inner.left, path, imports, families, seen) || checkTaint(inner.right, path, imports, families, seen)
    );
  }

  return false;
}

function identifierIsTainted(
  node: t.Identifier,
  path: NodePath,
  imports: Map<string, ImportBinding>,
  families: Set<SourceFamily>,
  seen: Set<t.Node>,
): boolean {
  const binding = path.scope.getBinding(node.name);
  if (!binding) {
    return false;
  }
  // Same FUNCTION scope only — do not follow a binding declared in a
  // different function (a closure over an outer var, a separate function).
  if (binding.scope.getFunctionParent() !== path.scope.getFunctionParent()) {
    return false;
  }

  // C: the binding is an ipc-handler callback parameter (after `event`).
  if (families.has('C') && isIpcHandlerParam(binding.path)) {
    return true;
  }

  // One hop through the binding's initializer, resolved in the binding's own
  // scope so any identifiers inside it bind correctly.
  if (t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
    return checkTaint(binding.path.node.init, binding.path, imports, families, seen);
  }
  return false;
}

// ── Sources ──────────────────────────────────────────────────────────────

function isUntrustedSourceExpression(
  node: t.Node,
  path: NodePath,
  imports: Map<string, ImportBinding>,
  families: Set<SourceFamily>,
): boolean {
  if (families.has('B') && (isResponseBodyCall(node) || isAxiosCall(node, imports))) {
    return true;
  }
  if (families.has('A') && isUntrustedJsonParse(node, path)) {
    return true;
  }
  return false;
}

// `.json()` / `.text()` — a fetch/Response body parse.
function isResponseBodyCall(node: t.Node): boolean {
  return (
    t.isCallExpression(node) &&
    t.isMemberExpression(node.callee) &&
    !node.callee.computed &&
    t.isIdentifier(node.callee.property) &&
    (node.callee.property.name === 'json' || node.callee.property.name === 'text')
  );
}

// `axios(...)` or `axios.get(...)` / `.post(...)` etc., where `axios` is the
// imported axios binding.
function isAxiosCall(node: t.Node, imports: Map<string, ImportBinding>): boolean {
  if (!t.isCallExpression(node)) {
    return false;
  }
  const callee = node.callee;
  if (t.isIdentifier(callee)) {
    return imports.get(callee.name)?.source === 'axios';
  }
  if (t.isMemberExpression(callee) && t.isIdentifier(callee.object)) {
    return imports.get(callee.object.name)?.source === 'axios';
  }
  return false;
}

// `JSON.parse(x)` — untrusted UNLESS x is (inline, or one same-scope hop) a
// local filesystem read, which is local config, not external input.
function isUntrustedJsonParse(node: t.Node, path: NodePath): boolean {
  if (
    !t.isCallExpression(node) ||
    !t.isMemberExpression(node.callee) ||
    node.callee.computed ||
    !t.isIdentifier(node.callee.object) ||
    node.callee.object.name !== 'JSON' ||
    !t.isIdentifier(node.callee.property) ||
    node.callee.property.name !== 'parse'
  ) {
    return false;
  }
  const arg = node.arguments[0];
  return !!arg && t.isExpression(arg) && !argResolvesToLocalFsRead(arg, path);
}

function argResolvesToLocalFsRead(arg: t.Expression, path: NodePath): boolean {
  if (isFsReadCall(arg)) {
    return true;
  }
  if (t.isIdentifier(arg)) {
    const binding = path.scope.getBinding(arg.name);
    if (binding && t.isVariableDeclarator(binding.path.node) && binding.path.node.init) {
      return isFsReadCall(binding.path.node.init);
    }
  }
  return false;
}

function isFsReadCall(node: t.Node): boolean {
  return (
    t.isCallExpression(node) &&
    t.isMemberExpression(node.callee) &&
    !node.callee.computed &&
    t.isIdentifier(node.callee.property) &&
    (node.callee.property.name === 'readFileSync' || node.callee.property.name === 'readFile')
  );
}

// ipcMain.handle('ch', (event, arg1, ...) => ...) / ipcMain.on / ipcRenderer.on:
// every callback param EXCEPT the first (the event object) is untrusted. The
// event object itself is NOT a source (flagging it would be a false positive).
function isIpcHandlerParam(bindingPath: NodePath): boolean {
  const paramNode = bindingPath.node;
  if (!t.isIdentifier(paramNode)) {
    return false;
  }
  const fnPath = bindingPath.parentPath;
  if (!fnPath || !(fnPath.isArrowFunctionExpression() || fnPath.isFunctionExpression())) {
    return false;
  }
  const params = fnPath.node.params;
  const index = params.indexOf(paramNode);
  if (index <= 0) {
    return false; // not found, or the first (event) param
  }
  // The function must be the callback argument of an ipc handler registration.
  const callPath = fnPath.parentPath;
  if (!callPath || !callPath.isCallExpression()) {
    return false;
  }
  const callee = callPath.node.callee;
  return (
    t.isMemberExpression(callee) &&
    !callee.computed &&
    t.isIdentifier(callee.property) &&
    (callee.property.name === 'handle' || callee.property.name === 'on') &&
    t.isIdentifier(callee.object) &&
    (callee.object.name === 'ipcMain' || callee.object.name === 'ipcRenderer')
  );
}

// ── Filesystem-path sink ───────────────────────────────────────────────────

// fs.readFile/writeFile/unlink/createWriteStream(...) etc. whose first arg is
// the path. `fs` is resolved via import bindings (node:fs / fs / fs/promises)
// or an inline require. A path built through path.join(...) is out of scope.
export function fsPathSinkArg(
  call: t.CallExpression,
  imports: Map<string, ImportBinding>,
): t.Node | undefined {
  const callee = call.callee;
  if (!t.isMemberExpression(callee) || callee.computed || !t.isIdentifier(callee.property)) {
    return undefined;
  }
  if (!FS_PATH_METHODS.has(callee.property.name)) {
    return undefined;
  }

  const object = callee.object;
  let source: string | undefined;
  if (t.isIdentifier(object)) {
    source = imports.get(object.name)?.source;
  } else {
    source = requireSource(object); // require('fs').readFile(...)
  }

  return source && FS_MODULE_SOURCES.has(source) ? call.arguments[0] : undefined;
}

function unwrap(node: t.Node): t.Node {
  if (t.isAwaitExpression(node)) {
    return unwrap(node.argument);
  }
  if (t.isTSAsExpression(node) || t.isTSNonNullExpression(node) || t.isTSSatisfiesExpression(node)) {
    return unwrap(node.expression);
  }
  return node;
}
