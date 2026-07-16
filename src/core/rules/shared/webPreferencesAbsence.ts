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
      reason: `On the target's Electron ${major}, this option's default is not safe (the safe default starts at ${safeSinceMajor}+).`,
    };
  }
  return {
    report: true,
    reason: `Couldn't determine the project's Electron version — on an older version (below ${safeSinceMajor}), the default is unsafe.`,
  };
}
