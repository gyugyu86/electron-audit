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
const INCLUDED_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx']);
// HTML is collected separately and read ONLY to extract <meta> CSP — it is
// never JS-parsed or run through the node rules (HTML has no JS sinks).
const HTML_EXTENSIONS = new Set(['.html', '.htm']);
const EXCLUDED_DIR_NAMES = new Set(['node_modules', 'dist', 'build', 'out', '.git']);

export function scanProject(options: ScanOptions): ScanResult {
  const rootDir = path.resolve(options.rootDir);
  const rootRealPath = realpathSync(rootDir);
  const maxFileSizeBytes = options.maxFileSizeBytes ?? DEFAULT_MAX_FILE_SIZE_BYTES;
  const packageJsonMainPath = resolvePackageJsonMain(rootDir);

  const counters = { skippedOversized: 0, skippedOutsideRoot: 0 };
  const collected = collectFiles(rootDir, rootRealPath, new Set([rootRealPath]), counters);

  const files: ScannedFile[] = [];
  for (const filePath of collected.source) {
    if (statSync(filePath).size > maxFileSizeBytes) {
      counters.skippedOversized += 1;
      continue;
    }

    const draft: ScannedFile = { path: filePath, content: readFileSync(filePath, 'utf8'), role: 'renderer' };
    const classification = classifyFileRole({ file: draft, packageJsonMainPath });
    files.push({ ...draft, role: classification.role });
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

function resolvePackageJsonMain(rootDir: string): string | undefined {
  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { main?: string };
    return parsed.main ? path.resolve(rootDir, parsed.main) : undefined;
  } catch {
    return undefined;
  }
}

interface WalkCounters {
  skippedOversized: number;
  skippedOutsideRoot: number;
}

interface CollectedFiles {
  source: string[]; // .js/.ts/.jsx/.tsx — JS-parsed and run through node rules
  html: string[]; // .html/.htm — read only for <meta> CSP extraction
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
  const result: CollectedFiles = { source: [], html: [] };
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
        classifyByExtension(real, entry.name, result);
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
      classifyByExtension(fullPath, entry.name, result);
    }
  }

  return result;
}

function classifyByExtension(filePath: string, name: string, result: CollectedFiles): void {
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
