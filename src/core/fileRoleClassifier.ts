import path from 'node:path';
import type { FileRole, ScannedFile } from './types.js';

export interface ClassifyFileRoleInput {
  file: ScannedFile;
  // Every path a package.json in the project names as its entry point — the
  // root manifest and any nested one. A plural set rather than a single root
  // value because a monorepo keeps the real entry in a workspace package, and
  // "some manifest declares this file the entry point" is one kind of fact
  // however deep the manifest sits.
  mainPaths?: readonly string[];
  preloadPaths?: readonly string[];
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

// Directory names that a project uses to separate the processes. The weakest
// signal in this file, and the last one consulted — see the ordering note.
const ROLE_DIR_NAMES: ReadonlyMap<string, FileRole> = new Map([
  ['preload', 'preload'],
  ['main', 'main'],
  ['renderer', 'renderer'],
]);

// What does the directory layout claim this file is? Checked in the order
// above, so a path containing both `preload` and `main` reads as preload —
// the more specific claim, and the order the accuracy figure was measured
// with.
function roleFromDirectoryLayout(filePath: string): FileRole | undefined {
  const directories = new Set(
    filePath
      .split(path.sep)
      .slice(0, -1)
      .map((segment) => segment.toLowerCase()),
  );
  for (const [name, role] of ROLE_DIR_NAMES) {
    if (directories.has(name)) {
      return role;
    }
  }
  return undefined;
}

// Priority order: a path some package.json names as its entry point ->
// webPreferences.preload path(s) found elsewhere in the project -> build
// tooling -> filename heuristic (main.ts, preload.ts, renderer.ts, ...) ->
// the directory layout. When none of these match, the answer is 'renderer'
// with `confident: false`.
//
// The order is the whole safety argument, so it is worth being explicit about
// why the directory layout goes last. A directory called `main` does not
// reliably mean the main process: measured on a real app, `ts/windows/main/`
// is the MAIN WINDOW, a sibling of `about/`, `loading/` and `permissions/`,
// and the files inside it are preload and renderer code. Four files there
// would be mislabelled `main` by the layout alone. Every one of them carries
// `.preload.` in its filename, so running the filename check first answers
// them correctly and the layout never gets asked. Move the layout check above
// the filename check and those four go wrong — which is what the ordering
// test pins.
//
// The layout check is still worth having: across the corpora it agrees with
// what files actually import in 214 of the 218 cases where there was any
// electron API to judge by, and every file it newly labels was verified by
// hand to be right. It is a convention rather than a fact, which is exactly
// why it only speaks when nothing more certain has.
//
// READ THAT FALLBACK CAREFULLY: `confident: false` never means "probably a
// renderer". It means none of the checks matched, and 'renderer' is only
// there because the field had to hold something. Measured across the
// corpora, every single `renderer` this function returns is that fallback —
// it has no path that concludes "renderer" on evidence — and 55 of those
// files have `main/` or `preload/` in their own path.
//
// So the caller drops the role entirely rather than reporting it. An earlier
// version of this comment asked callers to lower the resulting Finding's
// `confidence` instead; that was the wrong lever. `confidence` states how
// sure the rule is that the code is dangerous, which has nothing to do with
// how sure we are about which process the file runs in — conflating them
// would have let a path heuristic weaken a real security verdict. Staying
// quiet costs a reader some context; saying "renderer" when we do not know
// tells them something false, and on 55 files it contradicts the path
// printed on the same line. Severity, confidence and the exit code are
// untouched by any of this.
//
// `build` sits BELOW main and preload on purpose. A file the manifest names as
// the entry point is the main process no matter where it lives, and the same
// goes for a file a window actually loads as its preload; those are facts
// about how the app runs, while the build check is a path convention.
export function classifyFileRole(input: ClassifyFileRoleInput): FileRoleClassification {
  const resolvedFilePath = path.resolve(input.file.path);

  if (input.mainPaths?.some((mainPath) => path.resolve(mainPath) === resolvedFilePath)) {
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

  // Reported as a determination, not withheld like the fallback below it.
  // `confident: false` means "do not show this", so treating the layout as
  // unsure would be the same as not having it — and the evidence says it is
  // right: every finding it newly labels sits in a file whose imports (or, for
  // two of them, an `@sentry/electron/main` vs `/renderer` subpath) confirm
  // the role. What keeps that honest is the ordering above, not this line.
  const layoutRole = roleFromDirectoryLayout(input.file.path);
  if (layoutRole) {
    return { role: layoutRole, confident: true };
  }

  return { role: 'renderer', confident: false };
}
