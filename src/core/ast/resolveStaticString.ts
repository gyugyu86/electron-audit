import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';
import { resolveConstIdentifier } from './constFolding.js';

// Companion to isStaticSafeLiteral: where that answers "can an attacker
// influence this?", this answers "what concrete string does it evaluate
// to?" — needed by EA040/EA042 to read a URL's scheme/host once the value
// is known static. Returns undefined for anything not statically resolvable
// to a string (a variable that doesn't const-fold, a call, member access, a
// template/concat with a dynamic part). Handles the same node shapes as
// isStaticSafeLiteral so the two agree on what "static" means.
export function resolveStaticStringValue(node: t.Node, path: NodePath): string | undefined {
  return resolve(node, path, new Set());
}

function resolve(node: t.Node, path: NodePath, seen: Set<t.Node>): string | undefined {
  if (seen.has(node)) {
    return undefined;
  }
  seen.add(node);

  if (t.isStringLiteral(node)) {
    return node.value;
  }
  if (t.isNumericLiteral(node) || t.isBooleanLiteral(node)) {
    return String(node.value);
  }

  if (t.isIdentifier(node)) {
    const resolved = resolveConstIdentifier(node.name, path);
    return resolved ? resolve(resolved, path, seen) : undefined;
  }

  if (t.isTemplateLiteral(node)) {
    let out = '';
    for (let i = 0; i < node.quasis.length; i += 1) {
      out += node.quasis[i]?.value.cooked ?? '';
      if (i < node.expressions.length) {
        const expr = node.expressions[i];
        if (!expr || t.isTSType(expr)) {
          return undefined;
        }
        const part = resolve(expr, path, seen);
        if (part === undefined) {
          return undefined;
        }
        out += part;
      }
    }
    return out;
  }

  if (t.isBinaryExpression(node) && node.operator === '+' && !t.isPrivateName(node.left)) {
    const left = resolve(node.left, path, seen);
    const right = resolve(node.right, path, seen);
    return left !== undefined && right !== undefined ? left + right : undefined;
  }

  return undefined;
}
