import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { resolveConstIdentifier } from './constFolding.js';

// Resolves `fn()` — a call to a same-file function — to the object literal it
// unconditionally returns, but ONLY when that literal is a sound stand-in for
// the call's value at this call site. It exists so the extremely common
// `new BrowserWindow(getOptions())` idiom is analyzed by the webPreferences
// extractor instead of written off as fully dynamic.
//
// This is a distinct primitive from constFolding.resolveConstIdentifier
// (which maps an identifier to its const initializer): the input is a call,
// the analysis is over a function body, and it handles function declarations
// too. It reuses resolveConstIdentifier for the const-function sub-case rather
// than reimplementing const resolution.
//
// The failure mode to avoid is treating a dangerous config as safe, which
// would let the exit-code gate pass a real vulnerability. Every condition
// below must hold; any doubt returns undefined and the caller keeps its
// 'dynamic' verdict (which still fires, heuristically). Deliberately stricter
// than strictly necessary in places (e.g. rejecting ALL parameters, not just
// ones the return references) — over-rejection only costs a heuristic report,
// under-rejection costs a missed critical.
export function resolveLocalFunctionReturnObject(
  callNode: t.CallExpression,
  path: NodePath,
): t.ObjectExpression | undefined {
  // Bare-identifier callee only — `obj.getOptions()` can't be bound to a
  // single local function statically.
  const callee = callNode.callee;
  if (!t.isIdentifier(callee)) {
    return undefined;
  }

  const fn = resolveLocalFunction(callee.name, path);
  if (!fn) {
    return undefined;
  }

  // Condition: return must not depend on arguments. A parameterless function
  // trivially satisfies this and covers the config-builder idiom; a function
  // that takes any argument could return a different value per call site, so
  // reject it outright rather than trying to prove the return ignores its
  // params.
  if (fn.params.length > 0) {
    return undefined;
  }

  return unconditionalReturnedObject(fn);
}

// The callee names a same-file, non-reassigned function: either a function
// declaration, or a `const` bound to an arrow/function expression. `let`/`var`
// (reassignable), import/require (cross-file), and any binding with a write
// are excluded. `getBinding` respects scope, so a shadowing local binding is
// resolved correctly and rejected here if it isn't a function.
function resolveLocalFunction(name: string, path: NodePath): t.Function | undefined {
  const binding = path.scope.getBinding(name);
  if (!binding || binding.constantViolations.length > 0) {
    return undefined;
  }
  if (binding.path.isFunctionDeclaration()) {
    return binding.path.node;
  }
  if (binding.kind === 'const') {
    const init = resolveConstIdentifier(name, path);
    if (init && (t.isArrowFunctionExpression(init) || t.isFunctionExpression(init))) {
      return init;
    }
  }
  return undefined;
}

// The function's body must yield exactly one object literal, unconditionally:
//   - concise arrow `() => ({ … })`, or
//   - a block whose only return is a direct, last, top-level statement, with
//     no branching/looping/try before it and no other return anywhere.
// Leading `const`/expression/declaration statements are allowed (they cannot
// change WHICH object is returned). The returned object must have no spread
// (`{ ...base, … }` could carry unknowable fields).
function unconditionalReturnedObject(fn: t.Function): t.ObjectExpression | undefined {
  const body = fn.body;

  if (!t.isBlockStatement(body)) {
    const expr = unwrap(body);
    return t.isObjectExpression(expr) && !hasSpread(expr) ? expr : undefined;
  }

  let returned: t.ObjectExpression | undefined;
  const statements = body.body;
  for (let i = 0; i < statements.length; i += 1) {
    const statement = statements[i];
    if (t.isReturnStatement(statement)) {
      // Only one return, and it must be the final statement — anything else is
      // a conditional/early return shape we won't reason about.
      if (returned !== undefined || i !== statements.length - 1 || statement.argument == null) {
        return undefined;
      }
      const expr = unwrap(statement.argument);
      if (!t.isObjectExpression(expr) || hasSpread(expr)) {
        return undefined;
      }
      returned = expr;
      continue;
    }
    // Benign leading statements can't alter the returned object. Anything with
    // control flow (if/switch/loops/try/throw/labeled/standalone-block) is
    // rejected — it may hide a branch or an earlier exit.
    if (
      !t.isVariableDeclaration(statement) &&
      !t.isExpressionStatement(statement) &&
      !t.isFunctionDeclaration(statement) &&
      !t.isClassDeclaration(statement) &&
      !t.isTSTypeAliasDeclaration(statement) &&
      !t.isTSInterfaceDeclaration(statement)
    ) {
      return undefined;
    }
  }
  return returned;
}

function hasSpread(obj: t.ObjectExpression): boolean {
  return obj.properties.some((prop) => t.isSpreadElement(prop));
}

function unwrap(node: t.Node): t.Node {
  let current = node;
  for (;;) {
    if (
      t.isTSAsExpression(current) ||
      t.isTSNonNullExpression(current) ||
      t.isTSTypeAssertion(current) ||
      t.isTSSatisfiesExpression(current) ||
      t.isParenthesizedExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
}
