import { describe, expect, it } from 'vitest';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { ALL_RULES } from '../../src/core/rules/index.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const CLEAN_ROOT = path.join(dirname, 'clean');

// The mirror image of the synthetic-vuln snapshot test: those apps must
// light up, THESE (real, correctly-written, genuinely-safe third-party
// apps) must stay silent. Runs the FULL ALL_RULES set, not a hardcoded
// subset, so every rule added is automatically re-checked here for false
// positives the moment it lands.
//
// The bar is "no high-confidence finding at severity critical/high" — the
// exact criterion the default exit code fails on (see cli/exitCode.ts). This
// is what "the tool would not break this app's CI" means, so it's the honest
// definition of a false positive for a known-good app.
//
// Heuristic findings are permitted (the tool saying "I can't be sure"). So is
// a high-confidence finding at medium/low/info severity: a genuinely-safe app
// can legitimately carry a minor true positive — e.g. electron-quick-start's
// CSP has `style-src 'unsafe-inline'`, which EA011 correctly reports at MEDIUM
// (inline styles are a limited attack surface, unlike inline scripts). That's
// a real finding, not an FP, and it must not gate a build. A high-confidence
// CRITICAL/HIGH finding, by contrast, is a certainty claim about a serious
// issue and must never land on a known-good app.
const GATING_SEVERITIES = new Set(['critical', 'high']);
function cleanAppDirs(): string[] {
  return readdirSync(CLEAN_ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name);
}

describe('clean corpus: no high-confidence false positives under ALL_RULES', () => {
  const apps = cleanAppDirs();

  it('has at least one clean app vendored', () => {
    expect(apps.length).toBeGreaterThan(0);
  });

  it.each(apps)('%s produces no gating (high-confidence critical/high) findings', (appName) => {
    const root = path.join(CLEAN_ROOT, appName);
    const scan = scanProject({ rootDir: root });
    const result = new RuleEngine(ALL_RULES).run(scan.files, scan.project);

    // On failure, surface each finding (rule + location) rather than just a
    // count — if a "clean" app trips a gating rule, whether it's a real FP
    // (rule bug) or a genuine issue in the sample is a human call, so the raw
    // finding has to be visible, not swallowed.
    const gating = result.findings
      .filter((f) => f.confidence === 'high' && GATING_SEVERITIES.has(f.severity))
      .map((f) => `${f.ruleId} ${f.severity} ${path.relative(root, f.file)}:${f.line}`);
    expect(gating, `unexpected gating findings in clean app "${appName}"`).toEqual([]);
  });
});
