import type { Binding, NodePath, Scope } from '@babel/traverse';
import * as t from '@babel/types';

// Recognizes a *dominating scheme-allowlist guard* for a call like
// `shell.openExternal(url)`: the call only executes on paths where the URL's
// scheme is statically proven to be a subset of http/https — the exact fix
// EA040's own recommendation prescribes, so flagging it would be the rule
// contradicting itself.
//
// The failure mode this module must avoid is a MISSED vulnerability, not a
// noisy report: every shape the matcher cannot prove falls back to "no
// guard" (the rule keeps firing). Deliberately NOT recognized, per that
// principle:
//   - validation split into a helper function (`if (isSafeUrl(url)) …`) —
//     cross-function tracking is outside this tool's stated scope;
//   - allowlists containing any scheme beyond http/https;
//   - allowlist arrays held in variables (mutable via push, which
//     constantViolations cannot see) — only inline array literals count;
//   - `new URL(x, base)` — the guard would check the *resolved* URL while
//     the sink receives the raw string;
//   - a shadowed `URL` binding (only the global constructor is trusted);
//   - any value that is reassigned anywhere in scope (guard and sink could
//     see different values).
//
// Recognized guard conditions (same function scope only; `P` is the
// protocol of `new URL(url)`, possibly via const intermediates or
// `const { protocol } = …` destructuring):
//   P === 'https:' / P == 'http:'          (and ||/&& combinations)
//   ['http:', 'https:'].includes(P)        (inline literal array only)
//   url.startsWith('https://')             (http(s) prefix literals)
// Domination shapes:
//   if (SAFE) { … openExternal(url) … }    (also ternary consequent)
//   if (!SAFE) { … } else { openExternal(url) }
//   if (!SAFE) return/throw;  … openExternal(url)   (early exit before it)

const SAFE_PROTOCOL_LITERALS = new Set(['http:', 'https:']);
const MAX_BINDING_HOPS = 5;

export function hasDominatingSchemeGuard(callPath: NodePath<t.CallExpression>, rawArg: t.Node): boolean {
  const arg = unwrap(rawArg);
  if (!t.isIdentifier(arg)) {
    return false;
  }
  const argBinding = callPath.scope.getBinding(arg.name);
  // No binding (free/global variable) or any write anywhere in scope — the
  // guard and the sink could observe different values. Bail to "no guard".
  if (!argBinding || argBinding.constantViolations.length > 0) {
    return false;
  }

  const boundary = callPath.getFunctionParent() ?? callPath.findParent((p) => p.isProgram());
  if (!boundary) {
    return false;
  }

  let child: NodePath = callPath;
  for (;;) {
    const parent: NodePath | null = child.parentPath;
    if (!parent) {
      break;
    }
    // Scope is present on every NodePath; hoist it so the node-type
    // narrowings below don't have to re-derive it.
    const parentScope = parent.scope;

    // (1) The call sits in the branch a safe condition selects.
    if (parent.isIfStatement() || parent.isConditionalExpression()) {
      const test = parent.node.test;
      if (child.key === 'consequent' && isSafeCondition(test, parentScope, argBinding, 0)) {
        return true;
      }
      if (child.key === 'alternate' && isRejectingCondition(test, parentScope, argBinding)) {
        return true;
      }
    }

    // (2) An `if (!SAFE) return/throw;` earlier in a block the call's
    // statement belongs to — every execution reaching the call passed it.
    if ((parent.isBlockStatement() || parent.isProgram()) && child.listKey === 'body' && typeof child.key === 'number') {
      const statements = parent.node.body;
      for (let i = 0; i < child.key; i += 1) {
        const statement = statements[i];
        if (
          t.isIfStatement(statement) &&
          guaranteesExit(statement.consequent) &&
          isRejectingCondition(statement.test, parentScope, argBinding)
        ) {
          return true;
        }
      }
    }

    if (parent === boundary) {
      break; // never look at conditions outside the call's own function
    }
    child = parent;
  }
  return false;
}

// True iff, when this condition is truthy, the argument's scheme is proven
// to be a member of SAFE_PROTOCOL_LITERALS.
function isSafeCondition(rawNode: t.Node, scope: Scope, argBinding: Binding, depth: number): boolean {
  if (depth > MAX_BINDING_HOPS) {
    return false;
  }
  const node = unwrap(rawNode);

  if (t.isLogicalExpression(node)) {
    if (node.operator === '||') {
      // Either side may select the path — both must independently prove safety.
      return (
        isSafeCondition(node.left, scope, argBinding, depth + 1) &&
        isSafeCondition(node.right, scope, argBinding, depth + 1)
      );
    }
    if (node.operator === '&&') {
      // Both sides hold — one safe conjunct is enough; extras only narrow.
      return (
        isSafeCondition(node.left, scope, argBinding, depth + 1) ||
        isSafeCondition(node.right, scope, argBinding, depth + 1)
      );
    }
    return false;
  }

  if (t.isBinaryExpression(node) && (node.operator === '===' || node.operator === '==')) {
    if (!t.isExpression(node.left)) {
      return false;
    }
    const left = unwrap(node.left);
    const right = unwrap(node.right);
    const literal = t.isStringLiteral(left) ? left : t.isStringLiteral(right) ? right : undefined;
    const other = t.isStringLiteral(left) ? right : left;
    return (
      literal !== undefined &&
      SAFE_PROTOCOL_LITERALS.has(literal.value) &&
      isProtocolOfArg(other, scope, argBinding, 0)
    );
  }

  if (t.isCallExpression(node)) {
    const callee = node.callee;
    if (!t.isMemberExpression(callee) || callee.computed || !t.isIdentifier(callee.property)) {
      return false;
    }

    if (callee.property.name === 'includes') {
      const array = unwrap(callee.object);
      if (
        t.isArrayExpression(array) &&
        array.elements.length > 0 &&
        array.elements.every((el) => el !== null && t.isStringLiteral(el) && SAFE_PROTOCOL_LITERALS.has(el.value)) &&
        node.arguments.length === 1 &&
        t.isExpression(node.arguments[0])
      ) {
        return isProtocolOfArg(node.arguments[0], scope, argBinding, 0);
      }
      return false;
    }

    if (callee.property.name === 'startsWith') {
      const receiver = unwrap(callee.object);
      if (
        t.isIdentifier(receiver) &&
        scope.getBinding(receiver.name) === argBinding &&
        node.arguments.length === 1
      ) {
        const prefix = node.arguments[0];
        return t.isStringLiteral(prefix) && isSafeStartsWithLiteral(prefix.value);
      }
      return false;
    }
  }

  return false;
}

// `!SAFE` — the shape early-exit guards and guarded else-branches use.
function isRejectingCondition(rawNode: t.Node, scope: Scope, argBinding: Binding): boolean {
  const node = unwrap(rawNode);
  return t.isUnaryExpression(node) && node.operator === '!' && isSafeCondition(node.argument, scope, argBinding, 0);
}

// A string that starts with one of these prefixes cannot carry any scheme
// other than http/https (a longer literal like 'https://example.com/' pins
// the scheme just as hard as the bare prefix).
function isSafeStartsWithLiteral(value: string): boolean {
  return value === 'http:' || value === 'https:' || value.startsWith('http://') || value.startsWith('https://');
}

// The expression is (or is a const alias of) `new URL(<arg>).protocol`.
function isProtocolOfArg(rawNode: t.Node, scope: Scope, argBinding: Binding, depth: number): boolean {
  if (depth > MAX_BINDING_HOPS) {
    return false;
  }
  const node = unwrap(rawNode);

  if (t.isMemberExpression(node) && !node.computed && t.isIdentifier(node.property) && node.property.name === 'protocol') {
    return isUrlObjectOfArg(node.object, scope, argBinding, true);
  }

  if (t.isIdentifier(node)) {
    const binding = scope.getBinding(node.name);
    if (!binding || binding.kind !== 'const' || binding.constantViolations.length > 0) {
      return false;
    }
    const declarator = declaratorOf(binding);
    if (!declarator || declarator.init == null) {
      return false;
    }
    // const protocol = <protocol-expression>;
    if (t.isIdentifier(declarator.id) && declarator.id.name === node.name) {
      return isProtocolOfArg(declarator.init, binding.scope, argBinding, depth + 1);
    }
    // const { protocol } = <url-object>;  /  const { protocol: p } = …;
    if (t.isObjectPattern(declarator.id)) {
      const destructuresProtocol = declarator.id.properties.some(
        (prop) =>
          t.isObjectProperty(prop) &&
          !prop.computed &&
          t.isIdentifier(prop.key) &&
          prop.key.name === 'protocol' &&
          t.isIdentifier(prop.value) &&
          prop.value.name === node.name,
      );
      return destructuresProtocol && isUrlObjectOfArg(declarator.init, binding.scope, argBinding, true);
    }
  }

  return false;
}

// The expression is (or is a const alias of) `new URL(<arg>)` — global URL
// constructor, exactly one argument, and that argument is the sink's value.
function isUrlObjectOfArg(rawNode: t.Node, scope: Scope, argBinding: Binding, allowHop: boolean): boolean {
  const node = unwrap(rawNode);

  if (t.isNewExpression(node)) {
    const callee = unwrap(node.callee);
    if (!t.isIdentifier(callee) || callee.name !== 'URL' || scope.getBinding('URL') !== undefined) {
      return false;
    }
    if (node.arguments.length !== 1 || !t.isExpression(node.arguments[0])) {
      return false;
    }
    const urlArg = unwrap(node.arguments[0]);
    return t.isIdentifier(urlArg) && scope.getBinding(urlArg.name) === argBinding;
  }

  if (allowHop && t.isIdentifier(node)) {
    const binding = scope.getBinding(node.name);
    if (!binding || binding.kind !== 'const' || binding.constantViolations.length > 0) {
      return false;
    }
    const declarator = declaratorOf(binding);
    return (
      declarator !== undefined &&
      t.isIdentifier(declarator.id) &&
      declarator.id.name === node.name &&
      declarator.init != null &&
      isUrlObjectOfArg(declarator.init, binding.scope, argBinding, false)
    );
  }

  return false;
}

function declaratorOf(binding: Binding): t.VariableDeclarator | undefined {
  if (binding.path.isVariableDeclarator()) {
    return binding.path.node;
  }
  const parent = binding.path.findParent((p) => p.isVariableDeclarator());
  return parent?.isVariableDeclarator() ? parent.node : undefined;
}

// The statement definitely leaves the function: a return/throw, or a block
// with a direct-child return/throw (sequential execution reaches it unless
// an earlier statement already exited).
function guaranteesExit(statement: t.Statement): boolean {
  if (t.isReturnStatement(statement) || t.isThrowStatement(statement)) {
    return true;
  }
  return (
    t.isBlockStatement(statement) &&
    statement.body.some((s) => t.isReturnStatement(s) || t.isThrowStatement(s))
  );
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
