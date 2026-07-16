import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { extractWebPreferences } from '../ast/webPreferencesExtractor.js';

const WHY_DANGEROUS =
  'nodeIntegration: true exposes the full Node.js API (fs, child_process, require, etc.) directly to the renderer ' +
  "process. If the page the renderer loads runs attacker-controlled script — via XSS or similar — it immediately " +
  'gains filesystem access and the ability to execute processes.';

const RECOMMENDATION = `Turn nodeIntegration off, and expose only the specific APIs you need through preload + contextBridge.

// main process
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});

// preload.js — expose only what's needed
contextBridge.exposeInMainWorld('api', {
  doSomething: () => ipcRenderer.invoke('do-something'),
});`;

export const EA001: NodeRule = {
  id: 'EA001',
  kind: 'node',
  severity: 'critical',
  target: 'BrowserWindow webPreferences.nodeIntegration',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const site of extractWebPreferences(context.ast, context.file.path)) {
      const { state } = site.webPreferences.nodeIntegration;

      // 'absent'/'explicit-false' is not EA001's call: the danger of absence
      // depends on the Electron version default, which EA002/003 handle.
      if (state === 'explicit-true') {
        findings.push({
          ruleId: 'EA001',
          severity: 'critical',
          confidence: 'high',
          file: site.file,
          line: site.line,
          target: 'new BrowserWindow({ webPreferences: { nodeIntegration: true } })',
          whyDangerous: WHY_DANGEROUS,
          recommendation: RECOMMENDATION,
        });
      } else if (state === 'dynamic') {
        findings.push({
          ruleId: 'EA001',
          severity: 'critical',
          confidence: 'heuristic',
          file: site.file,
          line: site.line,
          target: 'new BrowserWindow({ webPreferences: { nodeIntegration: <variable/expression> } })',
          whyDangerous: `${WHY_DANGEROUS} (The nodeIntegration value is a variable/expression, so its runtime value can't be determined statically — it could evaluate to true under some condition.)`,
          recommendation: RECOMMENDATION,
        });
      }
    }

    return findings;
  },
};
