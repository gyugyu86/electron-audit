import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { ALL_RULES } from '../../src/core/rules/index.js';
import type { Finding, FileRole } from '../../src/core/types.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(dirname, '../fixtures/file-role-build');

const scan = scanProject({ rootDir: FIXTURE });
const findings = new RuleEngine(ALL_RULES).run(scan.files, scan.project).findings;

const roleOf = (relative: string): FileRole | undefined =>
  scan.files.find((file) => file.path === path.join(FIXTURE, ...relative.split('/')))?.role;

const findingsIn = (relative: string): Finding[] =>
  findings.filter((finding) => finding.file === path.join(FIXTURE, ...relative.split('/')));

describe('build tooling is recognized', () => {
  it('marks a script under a project-root scripts/ directory', () => {
    expect(roleOf('scripts/sign-release.mjs')).toBe('build');
  });

  it('marks a packaging config recognized by filename at the project root', () => {
    expect(roleOf('forge.config.ts')).toBe('build');
  });

  it('labels the finding itself, without touching how it is graded', () => {
    const [finding] = findingsIn('scripts/sign-release.mjs');
    expect(finding?.role).toBe('build');
    // The role says where the code runs. It must not soften the verdict.
    expect(finding?.severity).toBe('critical');
    expect(finding?.confidence).toBe('high');
  });
});

// The two shapes below were measured misclassifying during the investigation.
// Both would state something false about a live app, which is worse than
// omitting the context entirely — hence a test each.
describe('application code is never relabelled as build tooling', () => {
  // A real desktop app has `<pkg>/src/shell/scripts/…` holding a sudo-prompt
  // call. Labelling that "build" would describe a runtime privilege-escalation
  // path as a packaging concern, undoing the EA021 promotion that exists to
  // make exactly this call stand out.
  it('does not treat a scripts/ directory nested under src/ as build', () => {
    const relative = 'packages/core/src/shell/scripts/elevate.js';
    expect(roleOf(relative)).not.toBe('build');

    const privileged = findingsIn(relative).find((finding) => finding.ruleId === 'EA021');
    expect(privileged).toBeDefined();
    expect(privileged?.severity).toBe('critical');
    expect(privileged?.role).not.toBe('build'); // still reported as app code
  });

  it('does not let a build-looking filename inside src/ win', () => {
    expect(roleOf('src/main/sign.ts')).not.toBe('build');
  });

  // package.json anchors EA060/EA062. It is not a scanned source file at all,
  // so it has no role — and in particular must not acquire `build` from the
  // filename patterns, which an earlier draft of them did.
  it('never labels a manifest-anchored finding as build', () => {
    const manifest = findingsIn('package.json');
    expect(manifest.length).toBeGreaterThan(0);
    for (const finding of manifest) {
      expect(finding.role).toBeUndefined();
    }
  });
});
