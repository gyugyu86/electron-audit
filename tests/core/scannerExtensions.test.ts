import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA020 } from '../../src/core/rules/EA020.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures/module-extensions');

// One fixture directory per extension, each holding exactly one file, each
// scanned on its own. That separation is what makes the check per-extension:
// drop `.mjs` from INCLUDED_EXTENSIONS and only the `.mjs` case goes red, so a
// regression names the extension it broke instead of collapsing into a single
// aggregate failure.
//
// Every case asserts a real FINDING, not merely that the file was collected.
// "Collected" is the cheap half of this change — the half that would still
// pass if the file reached the parser and was then silently dropped there.
const CASES = [
  { ext: '.mjs', dir: 'mjs', file: 'sign-macos.mjs' },
  { ext: '.cjs', dir: 'cjs', file: 'notarize.cjs' },
  { ext: '.mts', dir: 'mts', file: 'build.mts' },
  { ext: '.cts', dir: 'cts', file: 'hooks.cts' },
] as const;

describe('scanner: dual-module extensions are scanned and analyzed', () => {
  for (const testCase of CASES) {
    it(`reports the EA020 injection hiding in a ${testCase.ext} file`, () => {
      const scan = scanProject({ rootDir: path.join(FIXTURES, testCase.dir) });
      expect(scan.files.map((file) => path.basename(file.path))).toEqual([testCase.file]);

      const result = new RuleEngine([EA020]).run(scan.files);

      // Reached the parser and survived it (the `.mts`/`.cts` cases only pass
      // because the parser turns jsx off for them — their generics would fail
      // otherwise), then got analyzed rather than dropped mid-traverse.
      expect(result.filesScanned).toBe(1);
      expect(result.filesUnparsable).toBe(0);
      expect(result.filesAnalysisErrors).toBe(0);

      const findings = result.findings.filter((finding) => finding.ruleId === 'EA020');
      expect(findings).toHaveLength(1);
      expect(path.basename(findings[0].file)).toBe(testCase.file);
    });
  }
});
