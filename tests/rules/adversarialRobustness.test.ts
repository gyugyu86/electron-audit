import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { ALL_RULES } from '../../src/core/rules/index.js';
import { EA001 } from '../../src/core/rules/EA001.js';

// A static analyzer's threat model is untrusted INPUT (someone else's
// project), not itself — these lock in that malformed/huge/adversarial
// files get skipped, not crashed or hung on. Every fixture is generated
// into a scratch dir at test time rather than committed, so the repo never
// carries a multi-MB or genuinely-binary file.
let scratchDir: string | undefined;

function makeScratchDir(): string {
  scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ea-adversarial-'));
  return scratchDir;
}

afterEach(() => {
  if (scratchDir) {
    fs.rmSync(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

describe('oversized file handling', () => {
  it('skips a file over the configured size limit without reading/parsing it', () => {
    const dir = makeScratchDir();
    fs.writeFileSync(path.join(dir, 'huge.js'), 'x'.repeat(2000));
    fs.writeFileSync(path.join(dir, 'normal.js'), 'console.log(1);');

    const scan = scanProject({ rootDir: dir, maxFileSizeBytes: 1000 });

    expect(scan.skippedOversized).toBe(1);
    expect(scan.files).toHaveLength(1);
    expect(scan.files[0]?.path.endsWith('normal.js')).toBe(true);
  });

  it('does not skip anything under the default limit', () => {
    const dir = makeScratchDir();
    fs.writeFileSync(path.join(dir, 'normal.js'), 'console.log(1);');

    const scan = scanProject({ rootDir: dir });

    expect(scan.skippedOversized).toBe(0);
    expect(scan.files).toHaveLength(1);
  });

  // The clean-corpus gate leans on this case specifically. The only `.cjs` in
  // the vendored corpus is a multi-megabyte bundled package-manager binary,
  // and adding `.cjs` to the scanned extensions left the gate at zero only
  // because the size cap drops that file before anything reads it. That was a
  // measurement, not a guarantee: raise `maxFileSizeBytes` (or its default)
  // and the gate would start failing for a reason nothing in the repo
  // explains, so the behavior is pinned here for a dual-module extension too.
  //
  // The oversized file's CONTENT is deliberately unparsable, and that is what
  // separates the two skip paths. Taken by the size filter, it never reaches
  // the parser and `filesUnparsable` stays 0; if the size filter ever stops
  // taking it, the same file fails to parse and `filesUnparsable` becomes 1.
  // The pair of assertions therefore names WHICH path accounted for the file,
  // instead of merely observing that it produced no findings — both paths
  // produce none.
  it('skips an oversized .cjs through the size filter, not as a parse failure', () => {
    const dir = makeScratchDir();
    fs.writeFileSync(path.join(dir, 'bundled.cjs'), '\0not js at all {{{'.repeat(200));
    fs.writeFileSync(path.join(dir, 'normal.cjs'), 'console.log(1);');

    const scan = scanProject({ rootDir: dir, maxFileSizeBytes: 1000 });
    const result = new RuleEngine([EA001]).run(scan.files, scan.project);

    // Size path: counted here, and never handed to the engine at all.
    expect(scan.skippedOversized).toBe(1);
    expect(scan.files.map((file) => path.basename(file.path))).toEqual(['normal.cjs']);
    // Parse path: untouched, which is only true because the file never
    // arrived. Unparsable content that reached the parser would show up here.
    expect(result.filesScanned).toBe(1);
    expect(result.filesUnparsable).toBe(0);
    expect(result.filesAnalysisErrors).toBe(0);
  });
});

describe('pathological source content', () => {
  it('does not crash on thousands of nested parens (parser stack overflow is caught, not fatal)', () => {
    const dir = makeScratchDir();
    const depth = 5000;
    const deeplyNested = `let x = ${'('.repeat(depth)}1${')'.repeat(depth)};`;
    fs.writeFileSync(path.join(dir, 'deep.js'), deeplyNested);
    fs.writeFileSync(
      path.join(dir, 'vulnerable.js'),
      "const { BrowserWindow } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
    );

    const scan = scanProject({ rootDir: dir });
    const result = new RuleEngine([EA001]).run(scan.files);

    expect(scan.files).toHaveLength(2);
    expect(result.filesUnparsable).toBe(1); // deep.js
    expect(result.findings).toHaveLength(1); // vulnerable.js still gets analyzed
  });

  it('does not hang or crash when decorator syntax sits in an otherwise broken file', () => {
    // A decorator makes the parser retry with each decorator dialect. If the
    // file is ALSO malformed, every attempt fails — this locks in that the
    // bounded retry ends in a plain skip (counted, not crashed, not looping)
    // and that a normal file in the same project is still analyzed.
    const dir = makeScratchDir();
    fs.writeFileSync(path.join(dir, 'broken-decorated.ts'), '@Entity()\nexport class A { const ;;; ((( }\n');
    fs.writeFileSync(
      path.join(dir, 'vulnerable.js'),
      "const { BrowserWindow } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
    );

    const scan = scanProject({ rootDir: dir });
    const result = new RuleEngine([EA001]).run(scan.files);

    expect(result.filesUnparsable).toBe(1); // broken-decorated.ts, after both dialects failed
    expect(result.findings).toHaveLength(1); // vulnerable.js unaffected
  });

  it('does not crash on invalid UTF-8 / binary content saved with a .js extension', () => {
    const dir = makeScratchDir();
    // A JPEG-header-like byte sequence: not valid UTF-8, not valid JS.
    const binary = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x00, 0x01, 0x80, 0x81, 0x82]);
    fs.writeFileSync(path.join(dir, 'not-actually-js.js'), binary);
    fs.writeFileSync(path.join(dir, 'normal.js'), 'console.log(1);');

    const scan = scanProject({ rootDir: dir });
    const result = new RuleEngine([EA001]).run(scan.files);

    expect(scan.files).toHaveLength(2); // both pass the size/symlink gate — parsing is what rejects the binary one
    expect(result.filesUnparsable).toBe(1);
  });
});

describe('mid-analysis error isolation', () => {
  // A file can PARSE fine yet make babel's scope-crawl throw on the first
  // traverse() — the classic case is a same-scope duplicate binding (an
  // imported name redeclared as a function). This used to propagate out of a
  // rule's check() and kill the whole scan. It must instead skip that one file
  // and keep going, counted separately from a parse failure.
  const DUPLICATE_DECL = "import { helper } from './helper.js';\nfunction helper() {\n  return 1;\n}\nhelper();\n";
  const VULNERABLE = "const { BrowserWindow } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\n";

  it('skips a file that throws during analysis and still scans the rest — under the full rule set', () => {
    const dir = makeScratchDir();
    fs.writeFileSync(path.join(dir, 'crash.js'), DUPLICATE_DECL);
    fs.writeFileSync(path.join(dir, 'vulnerable.js'), VULNERABLE);

    const scan = scanProject({ rootDir: dir });
    // No throw despite crash.js — this is the regression the fix locks in.
    const result = new RuleEngine(ALL_RULES).run(scan.files);

    // crash.js parses, so it is NOT an "unparsable" — it is an analysis error.
    expect(result.filesUnparsable).toBe(0);
    expect(result.filesAnalysisErrors).toBe(1);
    expect(result.analysisErrors[0]?.file.endsWith('crash.js')).toBe(true);
    expect(result.analysisErrors[0]?.message).toContain('Duplicate declaration');

    // vulnerable.js is unaffected — its EA001 finding still comes through.
    expect(result.findings.some((f) => f.ruleId === 'EA001')).toBe(true);
  });

  it('an aggregate rule does not re-crash on the skipped file (excluded from parsedFiles)', () => {
    const dir = makeScratchDir();
    fs.writeFileSync(path.join(dir, 'crash.js'), DUPLICATE_DECL);
    fs.writeFileSync(path.join(dir, 'vulnerable.js'), VULNERABLE);

    const scan = scanProject({ rootDir: dir });
    // ALL_RULES includes aggregate rules (EA006/010/011/012/041) that traverse
    // parsedFiles; the run completing without throwing is the assertion.
    expect(() => new RuleEngine(ALL_RULES).run(scan.files)).not.toThrow();
  });
});
