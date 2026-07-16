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

// Priority order: package.json's `main` field -> webPreferences.preload
// path(s) found elsewhere in the project -> filename heuristic (main.ts,
// preload.ts, renderer.ts, ...). When none of these confidently match,
// default to 'renderer' with `confident: false` — callers should lower
// `confidence` on any resulting Finding for files classified this way.
export function classifyFileRole(input: ClassifyFileRoleInput): FileRoleClassification {
  const resolvedFilePath = path.resolve(input.file.path);

  if (input.packageJsonMainPath && path.resolve(input.packageJsonMainPath) === resolvedFilePath) {
    return { role: 'main', confident: true };
  }

  if (input.preloadPaths?.some((preloadPath) => path.resolve(preloadPath) === resolvedFilePath)) {
    return { role: 'preload', confident: true };
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
