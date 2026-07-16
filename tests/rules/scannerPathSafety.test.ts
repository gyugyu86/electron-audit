import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { scanProject } from '../../src/core/scanner.js';

// Symlinks are created at test time (never committed) since a real symlink
// in the repo would behave differently across checkout environments/OSes.
let scratchDir: string | undefined;

function makeScratchDir(): string {
  scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ea-symlink-'));
  return scratchDir;
}

afterEach(() => {
  if (scratchDir) {
    fs.rmSync(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

describe('scanner path-traversal / symlink safety', () => {
  it('does not follow a directory symlink that escapes the scanned root', () => {
    const base = makeScratchDir();
    const outsideDir = path.join(base, 'outside');
    const projectDir = path.join(base, 'project');
    fs.mkdirSync(outsideDir);
    fs.mkdirSync(projectDir);
    fs.writeFileSync(path.join(outsideDir, 'secret.js'), 'const x = 1;');
    fs.writeFileSync(path.join(projectDir, 'main.js'), 'console.log(1);');
    fs.symlinkSync(outsideDir, path.join(projectDir, 'escape-dir'));

    const scan = scanProject({ rootDir: projectDir });

    expect(scan.files.some((f) => f.path.includes('secret.js'))).toBe(false);
    expect(scan.files.some((f) => f.path.endsWith('main.js'))).toBe(true);
    expect(scan.skippedOutsideRoot).toBe(1);
  });

  it('does not follow a file symlink that escapes the scanned root', () => {
    const base = makeScratchDir();
    const outsideDir = path.join(base, 'outside');
    const projectDir = path.join(base, 'project');
    fs.mkdirSync(outsideDir);
    fs.mkdirSync(projectDir);
    const secretFile = path.join(outsideDir, 'secret.js');
    fs.writeFileSync(secretFile, 'const x = 1;');
    fs.writeFileSync(path.join(projectDir, 'main.js'), 'console.log(1);');
    fs.symlinkSync(secretFile, path.join(projectDir, 'escape-file.js'));

    const scan = scanProject({ rootDir: projectDir });

    expect(scan.files.some((f) => f.path.includes('secret.js'))).toBe(false);
    expect(scan.skippedOutsideRoot).toBe(1);
  });

  it('still follows a symlink that resolves to somewhere inside the scanned root', () => {
    const base = makeScratchDir();
    const projectDir = path.join(base, 'project');
    const realSubDir = path.join(projectDir, 'real');
    fs.mkdirSync(realSubDir, { recursive: true });
    fs.writeFileSync(path.join(realSubDir, 'inner.js'), 'console.log(1);');
    fs.symlinkSync(realSubDir, path.join(projectDir, 'alias'));

    const scan = scanProject({ rootDir: projectDir });

    // Same real file reachable both directly and through the in-root alias —
    // either way it must show up, and escaping must not have been triggered.
    expect(scan.files.some((f) => f.path.endsWith('inner.js'))).toBe(true);
    expect(scan.skippedOutsideRoot).toBe(0);
  });

  it('terminates instead of looping forever on a symlink cycle within the root', () => {
    const base = makeScratchDir();
    const projectDir = path.join(base, 'project');
    const subDir = path.join(projectDir, 'sub');
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(subDir, 'main.js'), 'console.log(1);');
    fs.symlinkSync(projectDir, path.join(subDir, 'loop')); // sub/loop -> project (an ancestor)

    const scan = scanProject({ rootDir: projectDir });

    expect(scan.files.filter((f) => f.path.endsWith('main.js'))).toHaveLength(1);
  });
});
