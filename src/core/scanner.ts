import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import type { HtmlCspSite, ProjectContext, ScannedFile } from './types.js';
import { classifyFileRole } from './fileRoleClassifier.js';
import { readElectronVersion } from './electronVersion.js';
import { readProjectMetadata } from './projectMetadata.js';
import { extractHtmlCspMetas } from './csp/htmlCspExtractor.js';

export interface ScanOptions {
  rootDir: string;
  // Files larger than this are skipped without being read into memory or
  // parsed — a static analyzer's threat model includes "someone points it
  // at a 200MB bundle.js", not just malformed source.
  maxFileSizeBytes?: number;
}

export interface ScanResult {
  files: ScannedFile[];
  // Counted separately from RuleEngine's parse-skip count: these never
  // even get read/parsed, for two different reasons.
  skippedOversized: number;
  skippedOutsideRoot: number;
  // Project-wide facts derived once here and threaded into every rule.
  project: ProjectContext;
}

const DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;
// `.mjs`/`.cjs`/`.mts`/`.cts` are the same JavaScript and TypeScript this tool
// already analyzes — only the module system differs — and real Electron
// projects keep build, packaging and code-signing scripts in exactly those
// files, which is where shelling out with an interpolated path is most common.
// Their absence here dropped them BEFORE the parser, so they appeared in no
// count at all: not `filesUnparsable`, not `filesAnalysisErrors`, just a
// smaller number of files scanned. A silent zero is the worst failure mode a
// scanner has, so this set must cover every extension the parser can handle.
//
// `.vue`/`.svelte` stay out deliberately. Their JS lives inside a `<script>`
// block that has to be extracted before anything can parse it — a separate
// feature, not another entry in this set.
const INCLUDED_EXTENSIONS = new Set([
  '.js',
  '.ts',
  '.jsx',
  '.tsx',
  '.mjs',
  '.cjs',
  '.mts',
  '.cts',
]);
// HTML is collected separately and read ONLY to extract <meta> CSP — it is
// never JS-parsed or run through the node rules (HTML has no JS sinks).
const HTML_EXTENSIONS = new Set(['.html', '.htm']);
const EXCLUDED_DIR_NAMES = new Set(['node_modules', 'dist', 'build', 'out', '.git']);

export function scanProject(options: ScanOptions): ScanResult {
  const rootDir = path.resolve(options.rootDir);
  const rootRealPath = realpathSync(rootDir);
  const maxFileSizeBytes = options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;

  const counters = { skippedOversized: 0, skippedOutsideRoot: 0 };
  const collected = collectFiles(rootDir, rootRealPath, new Set([rootRealPath]), counters);
  const mainPaths = resolveManifestMains(collected.manifests);

  const files: ScannedFile[] = [];
  for (const filePath of collected.source) {
    if (statSync(filePath).size > maxFileSizeBytes) {
      counters.skippedOversized += 1;
      continue;
    }

    const draft: ScannedFile = { path: filePath, content: readFileSync(filePath, 'utf8') };
    const classification = classifyFileRole({ file: draft, mainPaths });
    // The role is kept only when the classifier was sure of it. Its
    // unsure answer is always `renderer` — the fallback, not a finding about
    // the file — so storing it would put a guess where the rest of the code
    // expects a fact.
    files.push(classification.confident ? { ...draft, role: classification.role } : draft);
  }

  const htmlCspSites: HtmlCspSite[] = [];
  for (const htmlPath of collected.html) {
    if (statSync(htmlPath).size > maxFileSizeBytes) {
      counters.skippedOversized += 1;
      continue;
    }
    for (const meta of extractHtmlCspMetas(readFileSync(htmlPath, 'utf8'))) {
      htmlCspSites.push({ file: htmlPath, line: meta.line, value: meta.value });
    }
  }

  const metadata = readProjectMetadata(rootDir);
  const project: ProjectContext = {
    electronMajorVersion: readElectronVersion(rootDir),
    rootDir,
    packageJsonPath: metadata.packageJsonPath,
    dependencyNames: metadata.dependencyNames,
    packageJsonBuild: metadata.packageJsonBuild,
    htmlCspSites,
  };

  return {
    files,
    skippedOversized: counters.skippedOversized,
    skippedOutsideRoot: counters.skippedOutsideRoot,
    project,
  };
}

// Every entry point declared by a package.json anywhere in the scanned tree,
// not just the one at the root. Measured across real projects, the root
// manifest names a file that exists in only 2 of 17 — the rest either point at
// a bundler output that is not in source, or have no `main` at all because the
// app lives in a workspace package whose own manifest does name it.
//
// Any manifest counts, at any depth, and no notion of "nearest" is needed: a
// file either is declared an entry point by some manifest or it is not, and
// two manifests naming the same file is not a conflict. Depth costs nothing
// because the walk already excludes node_modules and the build output dirs, so
// only the project's own manifests are seen.
//
// A `main` that resolves to a directory is accepted through its index.js,
// which is how Node resolves it. One that resolves to nothing is dropped —
// that is the bundler-output case, and guessing where the real source lives
// would be exactly the invention this classifier avoids.
function resolveManifestMains(manifestPaths: readonly string[]): string[] {
  const entryPoints: string[] = [];
  for (const manifestPath of manifestPaths) {
    let main: unknown;
    try {
      main = (JSON.parse(readFileSync(manifestPath, 'utf8')) as { main?: unknown }).main;
    } catch {
      continue; // unparsable manifest — nothing to learn from it
    }
    if (typeof main !== 'string' || main === '') {
      continue;
    }
    const resolved = path.resolve(path.dirname(manifestPath), main);
    if (existsSync(resolved) && statSync(resolved).isFile()) {
      entryPoints.push(resolved);
      continue;
    }
    const asDirectoryIndex = path.join(resolved, 'index.js');
    if (existsSync(asDirectoryIndex)) {
      entryPoints.push(asDirectoryIndex);
    }
  }
  return entryPoints;
}

interface WalkCounters {
  skippedOversized: number;
  skippedOutsideRoot: number;
}

interface CollectedFiles {
  source: string[]; // every INCLUDED_EXTENSIONS file — JS-parsed and run through node rules
  html: string[]; // .html/.htm — read only for <meta> CSP extraction
  manifests: string[]; // package.json at any depth — read only for its `main` entry point
}

// Symlink- and cycle-aware: a symlink (file or directory) that resolves
// outside `rootRealPath` is never followed (path-traversal escape), and
// `visitedRealDirs` stops a symlink that loops back to an ancestor within
// the root from recursing forever.
function collectFiles(
  dir: string,
  rootRealPath: string,
  visitedRealDirs: Set<string>,
  counters: WalkCounters,
): CollectedFiles {
  const result: CollectedFiles = { source: [], html: [], manifests: [] };
  for (const entry of readDirEntriesSafe(dir)) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isSymbolicLink()) {
      let real: string;
      try {
        real = realpathSync(fullPath);
      } catch {
        continue; // broken symlink
      }
      if (!isWithinRoot(real, rootRealPath)) {
        counters.skippedOutsideRoot += 1;
        continue;
      }

      const stat = statSync(real);
      if (stat.isDirectory()) {
        if (EXCLUDED_DIR_NAMES.has(entry.name) || visitedRealDirs.has(real)) {
          continue;
        }
        visitedRealDirs.add(real);
        merge(result, collectFiles(real, rootRealPath, visitedRealDirs, counters));
      } else if (stat.isFile()) {
        classifyCollectedFile(real, entry.name, result);
      }
      continue;
    }

    if (entry.isDirectory()) {
      if (!EXCLUDED_DIR_NAMES.has(entry.name)) {
        merge(result, collectFiles(fullPath, rootRealPath, visitedRealDirs, counters));
      }
      continue;
    }

    if (entry.isFile()) {
      classifyCollectedFile(fullPath, entry.name, result);
    }
  }

  return result;
}

// Sorted by what the file is FOR, which is not always its extension:
// package.json is picked out by name because it is read for one field, never
// analyzed.
function classifyCollectedFile(filePath: string, name: string, result: CollectedFiles): void {
  if (name === 'package.json') {
    result.manifests.push(filePath);
    return;
  }
  const ext = path.extname(name);
  if (INCLUDED_EXTENSIONS.has(ext)) {
    result.source.push(filePath);
  } else if (HTML_EXTENSIONS.has(ext)) {
    result.html.push(filePath);
  }
}

function merge(into: CollectedFiles, from: CollectedFiles): void {
  into.source.push(...from.source);
  into.html.push(...from.html);
  into.manifests.push(...from.manifests);
}

function readDirEntriesSafe(dir: string) {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return []; // unreadable directory (permissions, race with deletion, ...) — skip quietly
  }
}

function isWithinRoot(candidateRealPath: string, rootRealPath: string): boolean {
  if (candidateRealPath === rootRealPath) {
    return true;
  }
  const relative = path.relative(rootRealPath, candidateRealPath);
  return !relative.startsWith('..') && !path.isAbsolute(relative);
}
