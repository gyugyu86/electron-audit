import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';
import { resolveConstIdentifier } from './constFolding.js';

// Determines whether an AST node's value is something an attacker cannot
// influence: a literal, a same-file `const` reference that folds (possibly
// through a chain of consts) to one, or a TemplateLiteral / BinaryExpression
// ('+') built entirely out of such safe pieces. Everything else — a
// function call, a member expression (process.env.X, obj.prop), a
// parameter, a let/var binding, an import binding — is NOT safe. Shared by
// EA020/EA021/EA022 (command injection) and, from the E group onward,
// EA040/EA042 (shell.openExternal / loadURL).
export function isStaticSafeLiteral(node: t.Node, path: NodePath): boolean {
  return checkSafeLiteral(node, path, new Set());
}

function checkSafeLiteral(node: t.Node, path: NodePath, seen: Set<t.Node>): boolean {
  if (seen.has(node)) {
    return false; // cyclic const reference — can't happen in valid JS, but don't loop forever
  }
  seen.add(node);

  if (t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node)) {
    return true;
  }

  if (t.isIdentifier(node)) {
    const resolved = resolveConstIdentifier(node.name, path);
    return resolved !== undefined && checkSafeLiteral(resolved, path, seen);
  }

  if (t.isTemplateLiteral(node)) {
    return node.expressions.every((expr) => checkSafeLiteral(expr, path, seen));
  }

  if (t.isBinaryExpression(node) && node.operator === '+' && !t.isPrivateName(node.left)) {
    return checkSafeLiteral(node.left, path, seen) && checkSafeLiteral(node.right, path, seen);
  }

  return false;
}
