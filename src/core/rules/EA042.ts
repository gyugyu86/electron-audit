import traverse from '@babel/traverse';
import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { resolveStaticStringValue } from '../ast/resolveStaticString.js';
import { isLocalhostHost, parseUrl } from '../url.js';
import { isLoadUrlCallee } from './shared/externalInteraction.js';

// Scope note: EA042 judges LITERAL URLs only. A variable/expression URL is
// left to F-group EA050 (dataflow) so E stays a shallow, syntactic pass and
// doesn't double-cover dataflow territory.
const RECOMMENDATION = `Load local content with loadFile where possible; if you must load something remote, use only a fixed, trusted https domain.

// vulnerable: loads remote/non-https content
win.loadURL('http://example.com/app');

// fixed: loads a local file
win.loadFile('index.html');`;

export const EA042: NodeRule = {
  id: 'EA042',
  kind: 'node',
  severity: 'medium',
  target: 'loadURL(<remote URL or non-https http>)',
  whyDangerous: "Loading remote content into a window means running code the app doesn't control.",
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    traverse(context.ast, {
      CallExpression(path) {
        if (!isLoadUrlCallee(path.node.callee)) {
          return;
        }
        const arg = path.node.arguments[0];
        if (!arg) {
          return;
        }

        const value = resolveStaticStringValue(arg, path);
        if (value === undefined) {
          return; // dynamic → EA050/F group, not EA042
        }

        const { scheme, host } = parseUrl(value);
        if (scheme === 'file' || !host || isLocalhostHost(host)) {
          return; // local file, non-network scheme, or dev localhost → silence
        }

        const insecure = scheme === 'http';
        const whyDangerous = insecure
          ? `loadURL loads remote content over http (non-https): ${value}. Beyond running remote code, the connection is exposed to tampering and interception in transit.`
          : `loadURL loads remote content: ${value}. Remote code the app doesn't control could run in this window.`;

        findings.push({
          ruleId: 'EA042',
          severity: 'medium',
          confidence: 'high',
          file: context.file.path,
          line: path.node.loc?.start.line ?? 0,
          target: `loadURL(${JSON.stringify(value)})`,
          whyDangerous,
          recommendation: RECOMMENDATION,
        });
      },
    });

    return findings;
  },
};
