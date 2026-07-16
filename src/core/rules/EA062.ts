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
  'Electron generally only ships security patches for roughly the latest 3 majors. A version significantly ' +
  "further behind than that may still carry known, unpatched Chromium/Node.js vulnerabilities. (The baseline " +
  "'latest' version is hardcoded in this tool and can lag behind the real latest, so verify the actual current " +
  'version yourself.)';

const RECOMMENDATION = `Upgrade the electron dependency to the latest stable major, and check the release notes for compatibility changes.

// package.json
"devDependencies": {
  "electron": "^<latest-major>.0.0"
}`;

export const EA062: AggregateRule = {
  id: 'EA062',
  kind: 'aggregate',
  severity: 'info',
  target: "The electron version in package.json is far behind the latest",
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
        target: `electron ${major}.x (${LATEST_KNOWN_ELECTRON_MAJOR - major} majors behind our baseline of ${LATEST_KNOWN_ELECTRON_MAJOR}.x)`,
        whyDangerous: WHY_DANGEROUS,
        recommendation: RECOMMENDATION,
      },
    ];
  },
};
