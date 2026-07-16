import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';

// Resolves an identifier to its initializer node IF it's bound by a
// same-file `const` declaration. `let`/`var` bindings and import/require
// bindings report a binding `kind` other than 'const', so they're excluded
// here automatically — a reassignable or cross-file value can't be trusted
// as a single static value. Only one level; callers that want to follow a
// chain of const-to-const references recurse on the result themselves.
export function resolveConstIdentifier(name: string, path: NodePath): t.Node | undefined {
  const binding = path.scope.getBinding(name);
  if (!binding || binding.kind !== 'const' || !t.isVariableDeclarator(binding.path.node)) {
    return undefined;
  }
  return binding.path.node.init ?? undefined;
}
