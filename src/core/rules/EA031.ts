import traverse from '@babel/traverse';
import type { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { collectImportBindings, type ImportBinding } from './shared/importBindings.js';

// The ipcRenderer methods that take a channel as their first argument and give
// the caller a capability with it — sending to a channel, invoking a handler,
// or subscribing to one. Removal methods (off/removeListener/
// removeAllListeners) also take a channel but only detach a listener, which is
// a different and much smaller concern, so they are deliberately not here.
const IPC_FORWARDING_METHODS = new Set(['send', 'invoke', 'sendSync', 'sendToHost', 'on', 'once']);

const WHY_DANGEROUS =
  'A function exposed through contextBridge takes the IPC channel from its caller and passes it straight to ' +
  'ipcRenderer. That turns the preload from a defined API surface into a general-purpose door onto every IPC ' +
  'channel in the app: renderer code — including anything injected into the page by an XSS — can invoke any main ' +
  'process handler the app registers, or subscribe to any channel and read what main sends back. The preload is ' +
  'the boundary that is supposed to decide which of those are reachable, and a caller-supplied channel removes ' +
  'that decision.';

const RECOMMENDATION = `Expose named operations whose channel is fixed in the preload, rather than a channel argument.

// vulnerable — the renderer picks the channel, so every handler is reachable
contextBridge.exposeInMainWorld('api', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  on: (channel, listener) => ipcRenderer.on(channel, listener),
});

// fixed — one method per operation, each with its channel written here
contextBridge.exposeInMainWorld('api', {
  readSettings: () => ipcRenderer.invoke('settings:read'),
  saveSettings: (settings) => ipcRenderer.invoke('settings:save', settings),
  onThemeChanged: (listener) => ipcRenderer.on('theme:changed', (_event, theme) => listener(theme)),
});

If a generic bridge is unavoidable, keep the decision in the preload by
checking the channel against an allowlist before forwarding it.`;

// `contextBridge` / `ipcRenderer` under their conventional local names, a
// renamed destructured import resolved through the import bindings, or a
// member of the electron namespace (`electron.ipcRenderer`) — the same three
// shapes the other electron-API matchers in this codebase accept.
function isElectronMember(node: t.Node, imports: Map<string, ImportBinding>, member: string): boolean {
  if (t.isIdentifier(node)) {
    if (node.name === member) {
      return true;
    }
    const binding = imports.get(node.name);
    return binding?.source === 'electron' && binding.importedName === member;
  }
  return t.isMemberExpression(node) && !node.computed && t.isIdentifier(node.property) && node.property.name === member;
}

// The object literal written inline at the call. Everything else — a const
// holding the same object, a call's return value, a namespace member — is left
// alone, and that is a deliberate miss rather than an oversight.
//
// Resolving a const was tried and measured. It found three more exposed
// functions, and all three guarded the channel against an allowlist before
// forwarding it — which is the fix this rule's own recommendation prescribes.
// Reporting code that has already applied the advice is the one thing this
// tool will not do (see EA040, which stays silent on a dominating scheme
// guard for the same reason), so the wider read was dropped rather than
// shipped with a known false-positive class.
//
// The way to get that coverage back is not to widen this, but to recognize a
// dominating channel-allowlist guard the way hasDominatingSchemeGuard does for
// schemes, and then read the wider forms safely. That is a v2 candidate: it is
// new judgment logic and needs its own measurement.
function exposedObject(callPath: NodePath<t.CallExpression>): NodePath<t.ObjectExpression> | undefined {
  const argument = callPath.get('arguments')[1];
  return argument?.isObjectExpression() ? argument : undefined;
}

interface ExposedFunction {
  fnPath: NodePath<t.ArrowFunctionExpression | t.FunctionExpression | t.ObjectMethod>;
  name: string;
}

function exposedFunction(propertyPath: NodePath): ExposedFunction | undefined {
  const name = (): string => {
    const key = (propertyPath.node as t.ObjectProperty | t.ObjectMethod).key;
    if (t.isIdentifier(key)) return key.name;
    if (t.isStringLiteral(key)) return key.value;
    return 'the exposed function';
  };
  if (propertyPath.isObjectMethod()) {
    return { fnPath: propertyPath, name: name() };
  }
  if (propertyPath.isObjectProperty()) {
    const value = propertyPath.get('value');
    if (value.isArrowFunctionExpression() || value.isFunctionExpression()) {
      return { fnPath: value, name: name() };
    }
  }
  return undefined;
}

// Does one of this function's own parameters end up as the channel — the first
// argument — of an ipcRenderer call? The identifier has to resolve to a
// parameter binding of THIS function, so a same-named variable from an
// enclosing scope, or a local shadowing the parameter, is not mistaken for it.
//
// Only the first argument counts. A parameter forwarded as a later argument is
// the payload, which is the ordinary way to write a bridge and not a finding.
function forwardedChannelMethod(
  fnPath: NodePath<t.ArrowFunctionExpression | t.FunctionExpression | t.ObjectMethod>,
  imports: Map<string, ImportBinding>,
): string | undefined {
  let method: string | undefined;
  fnPath.traverse({
    CallExpression(callPath) {
      if (method) {
        return;
      }
      const callee = callPath.node.callee;
      if (!t.isMemberExpression(callee) || callee.computed || !t.isIdentifier(callee.property)) {
        return;
      }
      if (!IPC_FORWARDING_METHODS.has(callee.property.name)) {
        return;
      }
      if (!isElectronMember(callee.object, imports, 'ipcRenderer')) {
        return;
      }
      const channel = callPath.node.arguments[0];
      if (!t.isIdentifier(channel)) {
        return;
      }
      const binding = callPath.scope.getBinding(channel.name);
      if (!binding || binding.kind !== 'param' || binding.scope.path.node !== fnPath.node) {
        return;
      }
      method = callee.property.name;
    },
  });
  return method;
}

// EA031 is a NodeRule, not an aggregate: both halves of the pattern — the
// contextBridge call and the ipcRenderer forward inside the function it
// exposes — are in the same file by construction, because the exposed
// function's body is what does the forwarding.
//
// It asks nothing about the file's role. `contextBridge` exists only in a
// preload, so the call is its own evidence of the context; gating on the role
// would only lose the files whose role could not be determined.
export const EA031: NodeRule = {
  id: 'EA031',
  kind: 'node',
  severity: 'medium',
  target: 'contextBridge exposes a function whose caller chooses the IPC channel',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];
    const imports = collectImportBindings(context.ast);

    traverse(context.ast, {
      CallExpression(callPath) {
        const callee = callPath.node.callee;
        if (!t.isMemberExpression(callee) || callee.computed || !t.isIdentifier(callee.property)) {
          return;
        }
        if (callee.property.name !== 'exposeInMainWorld') {
          return;
        }
        if (!isElectronMember(callee.object, imports, 'contextBridge')) {
          return;
        }
        const api = exposedObject(callPath);
        if (!api) {
          return;
        }

        for (const propertyPath of api.get('properties')) {
          const exposed = exposedFunction(propertyPath);
          if (!exposed) {
            continue;
          }
          const method = forwardedChannelMethod(exposed.fnPath, imports);
          if (!method) {
            continue;
          }
          findings.push({
            ruleId: 'EA031',
            severity: 'medium',
            confidence: 'high',
            file: context.file.path,
            line: propertyPath.node.loc?.start.line ?? 0,
            target: `contextBridge exposes ${exposed.name}(...), forwarding a caller-supplied channel to ipcRenderer.${method}`,
            whyDangerous: WHY_DANGEROUS,
            recommendation: RECOMMENDATION,
          });
        }
      },
    });

    return findings;
  },
};
