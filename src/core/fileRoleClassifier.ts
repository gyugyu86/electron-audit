import path from 'node:path';
import type { FileRole, ScannedFile } from './types.js';

export interface ClassifyFileRoleInput {
  file: ScannedFile;
  packageJsonMainPath?: string;
  preloadPaths?: string[];
}

export interface FileRoleClassification {
  role: FileRole;
  confident: boolean;
}

// Directory names that mark build tooling rather than application code. Note
// what is NOT here: `build`, `dist` and `out` are already excluded from the
// scan entirely, so they can never reach this function.
const BUILD_DIR_NAMES = new Set(['scripts', 'tools', 'build-tools', '.build']);

// Directory names that mark an application source tree. A build marker only
// counts when no source directory sits ABOVE it — see isBuildFile.
const APP_SOURCE_DIR_NAMES = new Set(['src', 'app', 'lib', 'source', 'renderer', 'main']);

// Filenames that are build tooling by convention.
const BUILD_FILE_PATTERNS: readonly RegExp[] = [
  /\.config\.(js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i,
  /^(forge|electron-builder|vite|webpack|rollup|esbuild|gulpfile|gruntfile)\./i,
  /^(after|before)(sign|pack|build|allartifact)/i,
  /^(notarize|codesign|sign)[-.]/i,
  /^sign\.(js|mjs|cjs|ts|mts|cts)$/i,
];

// Is this file build tooling — something that runs while the app is packaged,
// signed and released, rather than while the app runs?
//
// The point of the distinction is how a reader should weigh a finding, so the
// cost of getting it wrong is asymmetric. Calling runtime code "build" tells
// someone that a live privilege-escalation path is a packaging concern; the
// reverse merely omits context. Both guards below exist because measurement
// showed the naive version making exactly that dangerous mistake:
//
//  - A marker directory only counts when no application source directory sits
//    above it. `scripts/sign-macos.mjs` at a package root is build tooling;
//    `<pkg>/src/shell/scripts/enable-loopback.js` is application code that
//    happens to have a directory named "scripts" inside it, and in a real app
//    that shape holds a sudo-prompt call — a critical runtime finding that the
//    naive rule would have relabelled as build tooling.
//  - A filename pattern is ignored anywhere inside an application source tree,
//    for the same reason: `src/main/sign.ts` is app code.
//
// Deliberately conservative: an unrecognized build script stays whatever it
// was, which loses context but states nothing false.
function isBuildFile(filePath: string): boolean {
  const segments = filePath.split(path.sep);
  const directories = segments.slice(0, -1).map((segment) => segment.toLowerCase());

  const firstAppSource = directories.findIndex((dir) => APP_SOURCE_DIR_NAMES.has(dir));
  const firstBuildDir = directories.findIndex((dir) => BUILD_DIR_NAMES.has(dir));

  if (firstBuildDir >= 0 && (firstAppSource === -1 || firstBuildDir < firstAppSource)) {
    return true;
  }
  if (firstAppSource >= 0) {
    return false;
  }
  const baseName = path.basename(filePath);
  return BUILD_FILE_PATTERNS.some((pattern) => pattern.test(baseName));
}

// Priority order: package.json's `main` field -> webPreferences.preload
// path(s) found elsewhere in the project -> build tooling -> filename
// heuristic (main.ts, preload.ts, renderer.ts, ...). When none of these
// confidently match, default to 'renderer' with `confident: false` — callers
// should lower `confidence` on any resulting Finding for files classified
// this way.
//
// `build` sits BELOW main and preload on purpose. A file the manifest names as
// the entry point is the main process no matter where it lives, and the same
// goes for a file a window actually loads as its preload; those are facts
// about how the app runs, while the build check is a path convention.
export function classifyFileRole(input: ClassifyFileRoleInput): FileRoleClassification {
  const resolvedFilePath = path.resolve(input.file.path);

  if (input.packageJsonMainPath && path.resolve(input.packageJsonMainPath) === resolvedFilePath) {
    return { role: 'main', confident: true };
  }

  if (input.preloadPaths?.some((preloadPath) => path.resolve(preloadPath) === resolvedFilePath)) {
    return { role: 'preload', confident: true };
  }

  if (isBuildFile(input.file.path)) {
    return { role: 'build', confident: true };
  }

  const baseName = path.basename(input.file.path).toLowerCase();
  if (baseName.includes('preload')) {
    return { role: 'preload', confident: true };
  }
  if (baseName.includes('main')) {
    return { role: 'main', confident: true };
  }

  return { role: 'renderer', confident: false };
}
