import * as t from '@babel/types';
import type { ImportBinding } from './importBindings.js';

// Recognizes `shell.openExternal` where `shell` is Electron's shell — either
// the conventional local name `shell`, a destructured import renamed to
// something else (resolved via import bindings), or a `<x>.shell` member
// (e.g. `electron.shell` / `require('electron').shell`).
export function isShellOpenExternalCallee(callee: t.Node, imports: Map<string, ImportBinding>): boolean {
  if (!t.isMemberExpression(callee) || callee.computed || !t.isIdentifier(callee.property)) {
    return false;
  }
  if (callee.property.name !== 'openExternal') {
    return false;
  }

  const object = callee.object;
  if (t.isIdentifier(object)) {
    if (object.name === 'shell') {
      return true;
    }
    const binding = imports.get(object.name);
    return binding?.source === 'electron' && binding.importedName === 'shell';
  }
  // `electron.shell.openExternal(...)` / `require('electron').shell.openExternal(...)`
  return t.isMemberExpression(object) && !object.computed && t.isIdentifier(object.property) && object.property.name === 'shell';
}

// Recognizes any `<receiver>.loadURL(...)` call. loadURL is a distinctive
// BrowserWindow/webContents method and the receiver is a runtime instance
// (not statically bindable to electron), so this matches by method name.
export function isLoadUrlCallee(callee: t.Node): boolean {
  return (
    t.isMemberExpression(callee) &&
    !callee.computed &&
    t.isIdentifier(callee.property) &&
    callee.property.name === 'loadURL'
  );
}
