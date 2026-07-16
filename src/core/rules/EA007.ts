import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { getWindowCallSites } from './shared/windowCallSites.js';

// The `enableRemoteModule` option (and the built-in `remote` module it turns
// on) was REMOVED in Electron 14. So `enableRemoteModule: true` is dangerous
// on < 14 (it exposes the remote module) but merely dead config on >= 14
// (the option is ignored) — the inverse of the version-gating in EA002/003,
// where an *absent* key is the risk on old versions.
const REMOTE_REMOVED_IN = 14;

const WHY_DANGEROUS =
  'enableRemoteModule: true는 렌더러가 메인 프로세스의 객체·모듈(app, BrowserWindow, fs 등)을 remote 모듈로 직접 ' +
  '동기 호출하게 해줍니다. nodeIntegration만큼은 아니어도 렌더러 침해 시 강력한 권한을 그대로 넘겨주는 통로가 되고, ' +
  '프로토타입 오염 등으로 악용되기 쉽습니다.';

const RECOMMENDATION = `enableRemoteModule를 끄고(제거하고), 필요한 기능은 preload + contextBridge + ipcRenderer로 명시적으로 노출하세요.

// preload.js
contextBridge.exposeInMainWorld('api', {
  getPath: () => ipcRenderer.invoke('get-path'),
});
// 메인
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
            target: 'enableRemoteModule: true (Electron 14+에서는 제거되어 무효)',
            whyDangerous: `이 설정은 Electron ${REMOTE_REMOVED_IN}부터 제거되어 실제 효력은 없습니다. 다만 남아 있는 죽은 설정이니 정리하는 게 좋습니다. (구버전에서라면: ${WHY_DANGEROUS})`,
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
            target: 'enableRemoteModule: true (electron 버전 불명)',
            whyDangerous: `${WHY_DANGEROUS} (electron 버전을 확인하지 못했습니다 — 14 미만이면 위험하고, 14 이상이면 무효인 죽은 설정입니다.)`,
          });
        }
      } else if (state === 'dynamic') {
        findings.push({
          ...base,
          severity: 'high',
          confidence: 'heuristic',
          target: 'enableRemoteModule: <변수/표현식>',
          whyDangerous: `${WHY_DANGEROUS} (값이 변수/표현식이라 실행 시점에 켜질 수 있습니다.)`,
        });
      }
      // absent / explicit-false → remote module not enabled → silent.
    }

    return findings;
  },
};
