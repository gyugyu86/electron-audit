import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import type { FileRole } from '../../src/core/types.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

function roleOf(fixture: string, relative: string): FileRole | undefined {
  const root = path.join(FIXTURES, ...fixture.split('/'));
  const scan = scanProject({ rootDir: root });
  const target = path.join(root, ...relative.split('/'));
  const file = scan.files.find((f) => f.path === target);
  expect(file, `${relative} was not scanned`).toBeDefined();
  return file?.role;
}

// A directory named for a process is the weakest signal the classifier has, so
// it is asked last. These tests are mostly about that ordering.
describe('the directory layout answers when nothing more certain does', () => {
  it('reads src/main/ as the main process', () => {
    expect(roleOf('file-role-layout/windowed', 'src/main/service.ts')).toBe('main');
  });

  it('reads src/renderer/ as the renderer', () => {
    expect(roleOf('file-role-layout/windowed', 'src/renderer/view.ts')).toBe('renderer');
  });

  // THE CASE THIS ORDERING EXISTS FOR. `ts/windows/main/` is the main WINDOW,
  // and the file inside it is a preload script. Measured on a real app, the
  // layout alone mislabels four such files as main; the filename check runs
  // first and answers correctly, so the layout is never reached.
  it('does not call a preload script "main" because a window is named main', () => {
    expect(roleOf('file-role-layout/windowed', 'ts/windows/main/start.preload.ts')).toBe('preload');
  });

  // A declared entry point is a fact; a directory name is a convention.
  it('lets a manifest entry point outrank the directory it sits in', () => {
    expect(roleOf('file-role-layout/manifest-in-renderer', 'src/renderer/entry.js')).toBe('main');
  });

  // The root manifest of a workspace names no entry point; the package that
  // holds the app does. Neither the filename nor the layout could answer here.
  it('finds the entry point a nested workspace manifest declares', () => {
    expect(roleOf('file-role-layout/nested-workspace', 'packages/desktop/src/bootstrap.js')).toBe('main');
  });

  // Build classification is unchanged by any of this: it is consulted before
  // the layout, and a build directory above an app-source one still wins.
  it('leaves build classification alone', () => {
    expect(roleOf('file-role-build', 'scripts/sign-release.mjs')).toBe('build');
    expect(roleOf('file-role-build', 'forge.config.ts')).toBe('build');
    // A src/ tree inside a scripts/ tree is still build tooling.
    expect(roleOf('file-role-build', 'packages/core/src/shell/scripts/elevate.js')).not.toBe('build');
  });

  // The layout recovers what a bundler-output manifest cannot name — the case
  // that used to come out with no role at all.
  it('recovers a main-process file whose manifest points at a bundler output', () => {
    expect(roleOf('file-role-confidence/bundled-main', 'src/main/bootstrap.ts')).toBe('main');
  });
});
