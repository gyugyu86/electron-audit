import type { AggregateRule, AggregateRuleContext, Finding } from '../types.js';

// Electron's latest stable major as of 2026-01 (this tool's knowledge
// cutoff). MANUALLY MAINTAINED — bump when updating the tool. Deliberately a
// hardcoded constant, not a network lookup: the scan must be deterministic
// and reproducible offline (CI runs with no network).
const LATEST_KNOWN_ELECTRON_MAJOR = 40;

// Flag only when clearly behind — Electron supports roughly the latest 3
// majors (~1 year). Being this many majors behind means running an
// end-of-life build that no longer gets security fixes. A generous threshold
// keeps false positives away (a merely-a-bit-behind app isn't flagged), and
// a version NEWER than our baseline is never flagged (our constant just went
// stale).
const STALE_THRESHOLD_MAJORS = 5;

const WHY_DANGEROUS =
  'Electron은 대략 최신 3개 메이저 버전만 보안 패치를 제공합니다. 그보다 크게 뒤처진 버전은 Chromium·Node.js의 ' +
  '알려진 취약점이 수정되지 않은 채 남아 있을 수 있습니다. (기준 최신 버전은 이 도구에 하드코딩되어 있어 실제보다 ' +
  '오래됐을 수 있으니, 정확한 최신 버전은 직접 확인하세요.)';

const RECOMMENDATION = `electron 의존성을 최신 안정 메이저로 올리고, 릴리스 노트의 호환성 변경사항을 확인하세요.

// package.json
"devDependencies": {
  "electron": "^<latest-major>.0.0"
}`;

export const EA062: AggregateRule = {
  id: 'EA062',
  kind: 'aggregate',
  severity: 'info',
  target: 'package.json의 electron 버전이 최신 대비 크게 뒤처짐',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: AggregateRuleContext): Finding[] {
    const major = context.project.electronMajorVersion;
    // Version unknown ("*", "latest", git URL, or no electron dep) → don't
    // guess; and a version newer than our (possibly stale) baseline is fine.
    if (major === undefined || LATEST_KNOWN_ELECTRON_MAJOR - major < STALE_THRESHOLD_MAJORS) {
      return [];
    }

    return [
      {
        ruleId: 'EA062',
        severity: 'info',
        // Staleness is judged against a hardcoded, hand-maintained baseline
        // that can itself be out of date — an advisory signal, not a
        // certainty claim.
        confidence: 'heuristic',
        file: context.project.packageJsonPath ?? 'package.json',
        line: 0,
        target: `electron ${major}.x (기준 최신 ${LATEST_KNOWN_ELECTRON_MAJOR}.x 대비 ${LATEST_KNOWN_ELECTRON_MAJOR - major} 메이저 뒤처짐)`,
        whyDangerous: WHY_DANGEROUS,
        recommendation: RECOMMENDATION,
      },
    ];
  },
};
