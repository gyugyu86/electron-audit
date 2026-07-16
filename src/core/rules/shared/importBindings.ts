import * as t from '@babel/types';
import type { File } from '@babel/types';

export interface ImportBinding {
  source: string;
  // The exported name pulled in — 'default' for `import x from 'm'` or
  // `const x = require('m')`, '*' for `import * as x from 'm'`, or the
  // actual named export otherwise.
  importedName: string;
}

// Maps each local identifier bound by an import/require at the top level of
// the file to which module (and which export) it came from. Only looks at
// Program.body — imports/requires inside a function body are rare enough,
// and out of scope for the same-file-only tracing this tool does anyway.
export function collectImportBindings(ast: File): Map<string, ImportBinding> {
  const bindings = new Map<string, ImportBinding>();

  for (const statement of ast.program.body) {
    if (t.isImportDeclaration(statement)) {
      collectEsmImport(statement, bindings);
      continue;
    }
    if (t.isVariableDeclaration(statement)) {
      collectRequireImports(statement, bindings);
    }
  }

  return bindings;
}

function collectEsmImport(statement: t.ImportDeclaration, bindings: Map<string, ImportBinding>): void {
  const source = statement.source.value;
  for (const specifier of statement.specifiers) {
    if (t.isImportDefaultSpecifier(specifier)) {
      bindings.set(specifier.local.name, { source, importedName: 'default' });
    } else if (t.isImportNamespaceSpecifier(specifier)) {
      bindings.set(specifier.local.name, { source, importedName: '*' });
    } else if (t.isImportSpecifier(specifier)) {
      const importedName = t.isIdentifier(specifier.imported) ? specifier.imported.name : specifier.imported.value;
      bindings.set(specifier.local.name, { source, importedName });
    }
  }
}

function collectRequireImports(statement: t.VariableDeclaration, bindings: Map<string, ImportBinding>): void {
  for (const declarator of statement.declarations) {
    const source = requireSource(declarator.init);
    if (!source) {
      continue;
    }

    if (t.isIdentifier(declarator.id)) {
      bindings.set(declarator.id.name, { source, importedName: 'default' });
      continue;
    }
    if (t.isObjectPattern(declarator.id)) {
      for (const prop of declarator.id.properties) {
        if (t.isObjectProperty(prop) && t.isIdentifier(prop.key) && t.isIdentifier(prop.value)) {
          bindings.set(prop.value.name, { source, importedName: prop.key.name });
        }
      }
    }
  }
}

// Exported so callers can also resolve an inline `require('m')` expression
// that was never assigned to a variable, e.g. `require('child_process').exec(...)`.
export function requireSource(node: t.Node | null | undefined): string | undefined {
  if (!node || !t.isCallExpression(node) || !t.isIdentifier(node.callee) || node.callee.name !== 'require') {
    return undefined;
  }
  const arg = node.arguments[0];
  return arg && t.isStringLiteral(arg) ? arg.value : undefined;
}
