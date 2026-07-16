import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
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
