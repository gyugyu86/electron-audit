import type { Finding, Severity } from '../core/types.js';

// 'default' — fail only on findings the tool is CERTAIN about and that matter
//   (high-confidence AND severity critical/high). Heuristic/info/low never
//   break a build: a static analyzer that fails CI on its own false positives
//   is one nobody keeps in their pipeline. This is the low-false-positive
//   philosophy carried all the way to the exit code.
// 'strict' — also fail on heuristic findings at severity critical/high (for
//   teams that want the tool to gate aggressively).
// 'none'   — never fail (exit 0 always); report is informational only.
export type FailMode = 'default' | 'strict' | 'none';

const FAIL_SEVERITIES: ReadonlySet<Severity> = new Set<Severity>(['critical', 'high']);

export function computeExitCode(findings: Finding[], mode: FailMode): 0 | 1 {
  if (mode === 'none') {
    return 0;
  }
  const shouldFail = findings.some(
    (finding) =>
      FAIL_SEVERITIES.has(finding.severity) && (mode === 'strict' || finding.confidence === 'high'),
  );
  return shouldFail ? 1 : 0;
}
