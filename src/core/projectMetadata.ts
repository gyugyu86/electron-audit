import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

export interface ProjectMetadata {
  packageJsonPath?: string;
  dependencyNames: Set<string>;
  packageJsonBuild?: unknown;
}

// Reads package.json ONCE for the project-wide facts the G-group rules need
// (dependency names, the electron-builder inline `build` field). Robust by
// construction: a missing or unparseable package.json yields empty metadata
// rather than throwing — the scanner threads whatever it finds into every
// rule's ProjectContext.
export function readProjectMetadata(rootDir: string): ProjectMetadata {
  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return { dependencyNames: new Set() };
  }

  let parsed: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    build?: unknown;
  };
  try {
    parsed = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as typeof parsed;
  } catch {
    return { packageJsonPath, dependencyNames: new Set() };
  }

  const dependencyNames = new Set<string>([
    ...Object.keys(parsed.dependencies ?? {}),
    ...Object.keys(parsed.devDependencies ?? {}),
  ]);

  return { packageJsonPath, dependencyNames, packageJsonBuild: parsed.build };
}
