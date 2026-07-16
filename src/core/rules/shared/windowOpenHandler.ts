import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { File } from '@babel/types';

export interface SetWindowOpenHandlerCall {
  line: number;
  // True only when the handler provably returns { action: 'allow' } with no
  // conditional path — i.e. it allows every requested window unconditionally.
  // A deny, a conditional, or a computed action reads as false (EA041's
  // unconditional-allow facet stays silent unless it's certain).
  unconditionalAllow: boolean;
}

// Finds `*.setWindowOpenHandler(handler)` calls (matched by method name, not
// receiver — the receiver is almost always webContents). Shared by both
// EA041 facets: the NodeRule reads `unconditionalAllow`, the absence
// AggregateRule only needs to know whether any such call exists at all.
export function findSetWindowOpenHandlerCalls(ast: File): SetWindowOpenHandlerCall[] {
  const calls: SetWindowOpenHandlerCall[] = [];

  traverse(ast, {
    CallExpression(path) {
      const callee = path.node.callee;
      if (
        !t.isMemberExpression(callee) ||
        callee.computed ||
        !t.isIdentifier(callee.property) ||
        callee.property.name !== 'setWindowOpenHandler'
      ) {
        return;
      }
      calls.push({
        line: path.node.loc?.start.line ?? 0,
        unconditionalAllow: isUnconditionalAllowHandler(path.node.arguments[0]),
      });
    },
  });

  return calls;
}

function isUnconditionalAllowHandler(handler: t.Node | undefined): boolean {
  if (!handler || (!t.isArrowFunctionExpression(handler) && !t.isFunctionExpression(handler))) {
    return false;
  }

  // Arrow with an expression body: `() => ({ action: 'allow' })`.
  if (t.isArrowFunctionExpression(handler) && !t.isBlockStatement(handler.body)) {
    return isAllowActionObject(handler.body);
  }

  // Block body: only "unconditional" if the single statement is
  // `return { action: 'allow' }`. Multiple statements or any branching means
  // we can't prove it always allows, so stay conservative (silent).
  if (t.isBlockStatement(handler.body)) {
    const body = handler.body.body;
    if (body.length !== 1) {
      return false;
    }
    const only = body[0];
    return !!only && t.isReturnStatement(only) && !!only.argument && isAllowActionObject(only.argument);
  }

  return false;
}

function isAllowActionObject(node: t.Node): boolean {
  if (!t.isObjectExpression(node)) {
    return false;
  }
  const actionProp = node.properties.find(
    (prop): prop is t.ObjectProperty =>
      t.isObjectProperty(prop) && !prop.computed && t.isIdentifier(prop.key) && prop.key.name === 'action',
  );
  return !!actionProp && t.isStringLiteral(actionProp.value) && actionProp.value.value === 'allow';
}
