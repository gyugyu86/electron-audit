export interface AbsenceVerdict {
  report: boolean;
  // Appended to the finding message when report is true; empty otherwise.
  reason: string;
}

// Decides whether a *missing* webPreferences key is dangerous, given the
// target's Electron major version and the version from which that key's
// secure default took effect (contextIsolation: 12, sandbox: 20). When it
// reports, callers use confidence 'heuristic' — an absent key is default
// reliance, not an explicit mistake, and for an unknown version it's a guess.
export function classifyMissingSecureDefault(major: number | undefined, safeSinceMajor: number): AbsenceVerdict {
  if (major !== undefined && major >= safeSinceMajor) {
    return { report: false, reason: '' };
  }
  if (major !== undefined) {
    return {
      report: true,
      reason: `대상 Electron ${major}에서는 이 옵션의 기본값이 안전하지 않습니다(안전 기본값은 ${safeSinceMajor}+부터).`,
    };
  }
  return {
    report: true,
    reason: `프로젝트의 Electron 버전을 확인할 수 없습니다 — 구버전(${safeSinceMajor} 미만)이면 기본값이 위험합니다.`,
  };
}
