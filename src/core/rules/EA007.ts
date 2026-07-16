import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

// The `enableRemoteModule` option (and the built-in `remote` module it turns
// on) was REMOVED in Electron 14. So `enableRemoteModule: true` is dangerous
// on < 14 (it exposes the remote module) but merely dead config on >= 14
// (the option is ignored) — the inverse of the version-gating in EA002/003,
// where an *absent* key is the risk on old versions.
const REMOTE_REMOVED_IN = 14;

const WHY_DANGEROUS =
  'enableRemoteModule: true lets the renderer synchronously call main-process objects and modules (app, ' +
  'BrowserWindow, fs, etc.) directly through the remote module. It\'s not as severe as nodeIntegration, but it\'s ' +
  'still a channel that hands over substantial privileges once the renderer is compromised, and it\'s an easy ' +
  'target for exploitation via prototype pollution and similar techniques.';

const RECOMMENDATION = `Turn enableRemoteModule off (remove it), and expose only what you need explicitly through preload + contextBridge + ipcRenderer.

// preload.js
contextBridge.exposeInMainWorld('api', {
  getPath: () => ipcRenderer.invoke('get-path'),
});
// main process
ipcMain.handle('get-path', () => app.getPath('userData'));`;

export const EA007: NodeRule = {
  id: 'EA007',
  kind: 'node',
  severity: 'high',
  target: 'BrowserWindow webPreferences.enableRemoteModule',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    const findings: Finding[] = [];
    const major = context.project.electronMajorVersion;

    for (const site of getWindowCallSites(context.ast, context.file.path)) {
      const state = site.webPreferences.enableRemoteModule.state;
      const base = { ruleId: 'EA007', file: site.file, line: site.line, recommendation: RECOMMENDATION } as const;

      if (state === 'explicit-true') {
        if (major !== undefined && major >= REMOTE_REMOVED_IN) {
          // Remote module removed in this version → ineffective dead config,
          // not a live risk. Report at info so it's surfaced for cleanup but
          // never gates a build.
          findings.push({
            ...base,
            severity: 'info',
            confidence: 'high',
            target: 'enableRemoteModule: true (removed and ineffective on Electron 14+)',
            whyDangerous: `This setting has had no effect since it was removed in Electron ${REMOTE_REMOVED_IN} — but it's still worth cleaning up as dead config. (On an older version it would matter: ${WHY_DANGEROUS})`,
          });
        } else if (major !== undefined) {
          // Known old version where the remote module still exists → real.
          findings.push({ ...base, severity: 'high', confidence: 'high', target: 'enableRemoteModule: true', whyDangerous: WHY_DANGEROUS });
        } else {
          // Version unknown — if it's < 14 this is dangerous, and an explicit
          // enableRemoteModule:true implies legacy intent. Report, heuristic.
          findings.push({
            ...base,
            severity: 'high',
            confidence: 'heuristic',
            target: 'enableRemoteModule: true (Electron version unknown)',
            whyDangerous: `${WHY_DANGEROUS} (Couldn't determine the Electron version — this is dangerous below 14, and dead/ineffective config at 14 or above.)`,
          });
        }
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          severity: 'high',
          confidence: 'heuristic',
          target: 'enableRemoteModule: <variable/expression>',
          whyDangerous: `${WHY_DANGEROUS} (The value is a variable/expression, so it could be turned on at runtime.)`,
        });
      }
      // absent / explicit-false → remote module not enabled → silent.
    }

    return findings;
  },
};
