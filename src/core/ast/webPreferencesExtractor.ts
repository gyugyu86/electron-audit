import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';
import type { File } from '@babel/types';
import { resolveConstIdentifier } from './constFolding.js';

export type BooleanPreferenceState =
  | { state: 'explicit-true' }
  | { state: 'explicit-false' }
  | { state: 'absent' }
  | { state: 'dynamic' };

export type StringPreferenceState =
  | { state: 'explicit'; value: string }
  | { state: 'absent' }
  | { state: 'dynamic' };

export interface NormalizedWebPreferences {
  nodeIntegration: BooleanPreferenceState;
  contextIsolation: BooleanPreferenceState;
  sandbox: BooleanPreferenceState;
  webSecurity: BooleanPreferenceState;
  allowRunningInsecureContent: BooleanPreferenceState;
  enableRemoteModule: BooleanPreferenceState;
  preload: StringPreferenceState;
}

export interface BrowserWindowCallSite {
  file: string;
  line: number;
  webPreferences: NormalizedWebPreferences;
}

const BOOLEAN_KEYS = [
  'nodeIntegration',
  'contextIsolation',
  'sandbox',
  'webSecurity',
  'allowRunningInsecureContent',
  'enableRemoteModule',
] as const;

// Walks a parsed file's AST for `new BrowserWindow({...})` call sites and
// normalizes each `webPreferences` object literal into the shape above.
// EA001-EA006 (nodeIntegration, contextIsolation, sandbox, webSecurity,
// allowRunningInsecureContent, and cross-window-mismatch) all read this
// output instead of each re-scanning BrowserWindow call sites themselves.
export function extractWebPreferences(ast: File, filePath: string): BrowserWindowCallSite[] {
  const callSites: BrowserWindowCallSite[] = [];

  traverse(ast, {
    NewExpression(nodePath) {
      if (!isBrowserWindowCallee(nodePath.node.callee)) {
        return;
      }

      const line = nodePath.node.loc?.start.line ?? 0;
      const firstArg = nodePath.node.arguments[0];
      const resolvedOptions = resolveOptionsObject(firstArg, nodePath);

      if (resolvedOptions.kind === 'absent') {
        callSites.push({ file: filePath, line, webPreferences: allFieldsState('absent') });
        return;
      }
      if (resolvedOptions.kind === 'dynamic') {
        callSites.push({ file: filePath, line, webPreferences: allFieldsState('dynamic') });
        return;
      }

      const webPreferencesProp = findProperty(resolvedOptions.node, 'webPreferences');
      if (!webPreferencesProp) {
        callSites.push({ file: filePath, line, webPreferences: allFieldsState('absent') });
        return;
      }

      callSites.push({
        file: filePath,
        line,
        webPreferences: resolveWebPreferencesObject(webPreferencesProp.value, nodePath),
      });
    },
  });

  return callSites;
}

type ResolvedOptions = { kind: 'object'; node: t.ObjectExpression } | { kind: 'absent' } | { kind: 'dynamic' };

function resolveOptionsObject(
  argNode: t.Node | null | undefined,
  path: NodePath,
): ResolvedOptions {
  if (!argNode) {
    return { kind: 'absent' };
  }
  if (t.isObjectExpression(argNode)) {
    return { kind: 'object', node: argNode };
  }
  if (t.isIdentifier(argNode)) {
    const resolved = resolveConstIdentifier(argNode.name, path);
    if (resolved && t.isObjectExpression(resolved)) {
      return { kind: 'object', node: resolved };
    }
  }
  return { kind: 'dynamic' };
}

// spread(...base) and cross-file references are out of scope for this
// primitive — either one makes the whole webPreferences object's contents
// unknowable statically, so we mark every field 'dynamic' and move on.
function resolveWebPreferencesObject(value: t.Node, path: NodePath): NormalizedWebPreferences {
  let objectNode: t.ObjectExpression | undefined;

  if (t.isObjectExpression(value)) {
    objectNode = value;
  } else if (t.isIdentifier(value)) {
    const resolved = resolveConstIdentifier(value.name, path);
    if (resolved && t.isObjectExpression(resolved)) {
      objectNode = resolved;
    }
  }

  if (!objectNode || hasSpread(objectNode)) {
    return allFieldsState('dynamic');
  }

  const result = {} as NormalizedWebPreferences;
  for (const key of BOOLEAN_KEYS) {
    result[key] = resolveBooleanState(objectNode, key, path);
  }
  result.preload = resolveStringState(objectNode, 'preload', path);
  return result;
}

function resolveBooleanState(obj: t.ObjectExpression, key: string, path: NodePath): BooleanPreferenceState {
  const prop = findProperty(obj, key);
  if (!prop) {
    return { state: 'absent' };
  }

  const literal = t.isIdentifier(prop.value) ? resolveConstIdentifier(prop.value.name, path) : prop.value;
  if (literal && t.isBooleanLiteral(literal)) {
    return { state: literal.value ? 'explicit-true' : 'explicit-false' };
  }
  return { state: 'dynamic' };
}

function resolveStringState(obj: t.ObjectExpression, key: string, path: NodePath): StringPreferenceState {
  const prop = findProperty(obj, key);
  if (!prop) {
    return { state: 'absent' };
  }

  const literal = t.isIdentifier(prop.value) ? resolveConstIdentifier(prop.value.name, path) : prop.value;
  if (literal && t.isStringLiteral(literal)) {
    return { state: 'explicit', value: literal.value };
  }
  return { state: 'dynamic' };
}

function findProperty(obj: t.ObjectExpression, key: string): t.ObjectProperty | undefined {
  return obj.properties.find(
    (prop): prop is t.ObjectProperty =>
      t.isObjectProperty(prop) &&
      !prop.computed &&
      ((t.isIdentifier(prop.key) && prop.key.name === key) || (t.isStringLiteral(prop.key) && prop.key.value === key)),
  );
}

function hasSpread(obj: t.ObjectExpression): boolean {
  return obj.properties.some((prop) => t.isSpreadElement(prop));
}

function isBrowserWindowCallee(callee: t.Expression | t.V8IntrinsicIdentifier): boolean {
  if (t.isIdentifier(callee)) {
    return callee.name === 'BrowserWindow';
  }
  if (t.isMemberExpression(callee) && !callee.computed && t.isIdentifier(callee.property)) {
    return callee.property.name === 'BrowserWindow';
  }
  return false;
}

function allFieldsState(state: 'absent' | 'dynamic'): NormalizedWebPreferences {
  return {
    nodeIntegration: { state },
    contextIsolation: { state },
    sandbox: { state },
    webSecurity: { state },
    allowRunningInsecureContent: { state },
    enableRemoteModule: { state },
    preload: { state },
  };
}
