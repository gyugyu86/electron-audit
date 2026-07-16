import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { extractWebPreferences } from '../ast/webPreferencesExtractor.js';

const WHY_DANGEROUS =
  'nodeIntegration: true는 렌더러 프로세스에 Node.js API(fs, child_process, require 등)를 그대로 노출합니다. ' +
  '렌더러가 로드하는 페이지에서 XSS 등으로 임의 스크립트가 실행되면 그 즉시 파일시스템 접근·프로세스 실행 권한까지 함께 탈취됩니다.';

const RECOMMENDATION = `nodeIntegration을 끄고, preload + contextBridge로 필요한 API만 선택적으로 노출하세요.

// 메인 프로세스
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});

// preload.js — 필요한 기능만 골라서 노출
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

      // 'absent'/'explicit-false' 판정은 EA001 소관이 아니다: absent의 위험성은
      // Electron 버전 기본값에 의존하므로 EA002/003이 다룬다.
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
          target: 'new BrowserWindow({ webPreferences: { nodeIntegration: <변수/표현식> } })',
          whyDangerous: `${WHY_DANGEROUS} (nodeIntegration 값이 변수/표현식으로 지정되어 있어 실행 시점 값을 정적으로 확정할 수 없습니다 — 조건에 따라 true가 될 수 있습니다.)`,
          recommendation: RECOMMENDATION,
        });
      }
    }

    return findings;
  },
};
