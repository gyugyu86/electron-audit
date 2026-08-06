import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { ALL_RULES } from '../../src/core/rules/index.js';
import type { Finding } from '../../src/core/types.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures/file-role-confidence');

function findingsFor(fixture: string, relative: string): Finding[] {
  const root = path.join(FIXTURES, fixture);
  const scan = scanProject({ rootDir: root });
  const result = new RuleEngine(ALL_RULES).run(scan.files, scan.project);
  const target = path.join(root, ...relative.split('/'));
  return result.findings.filter((finding) => finding.file === target);
}

// A role is reported only when the classifier determined it. Its fallback
// answer is always `renderer`, so reporting the fallback meant printing
// "renderer" wherever nothing matched — including on files whose own path
// says main/ or preload/.
//
// The fixture this uses matters. It was originally a file under `src/main/`
// with a bundler-output manifest, which the directory layout can now answer;
// that case moved to the layout tests, and the property lives here on a file
// nothing can speak for — no manifest entry, no marker in the filename, and a
// directory (`src/services/`) that says nothing about a process.
describe('an undetermined role is reported as no role, not as renderer', () => {
  it('omits the role when no signal identifies the process', () => {
    const findings = findingsFor('undetermined', 'src/services/telemetry.ts');

    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.role).toBeUndefined();
    }
  });

  // The point is silence, not a downgrade: dropping the role must not touch
  // how sure the rule is that the code is dangerous, nor how bad it would be.
  it('leaves severity and confidence exactly as they were', () => {
    const [finding] = findingsFor('undetermined', 'src/services/telemetry.ts');

    expect(finding?.ruleId).toBe('EA020');
    expect(finding?.severity).toBe('critical');
    expect(finding?.confidence).toBe('high');
  });
});

describe('a determined role is still reported', () => {
  it('resolves main from the manifest, with no filename hint to lean on', () => {
    const findings = findingsFor('resolved-main', 'entry.js');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((finding) => finding.role === 'main')).toBe(true);
  });

  it('resolves preload from the filename', () => {
    const findings = findingsFor('named-preload', 'preload.js');

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((finding) => finding.role === 'preload')).toBe(true);
  });

  // Build classification is always a determination, never a fallback, so it
  // is unaffected by this change — pinned here so a regression shows up as
  // "build stopped being reported" rather than as a silent gap.
  it('keeps reporting build, which is never a fallback', () => {
    const root = path.join(dirname, '../fixtures/file-role-build');
    const scan = scanProject({ rootDir: root });
    const findings = new RuleEngine(ALL_RULES).run(scan.files, scan.project).findings;

    const build = findings.filter((finding) => finding.role === 'build');
    expect(build.length).toBeGreaterThan(0);
  });
});
