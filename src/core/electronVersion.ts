import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

// Reads the major version of the target project's `electron` dependency from
// its package.json (devDependencies first, then dependencies). Returns
// undefined when there's no electron dependency or the range can't be parsed
// to a concrete major (e.g. "*", "latest", a git URL) — callers treat that
// as "version unknown", not "safe".
export function readElectronVersion(rootDir: string): number | undefined {
  const packageJsonPath = path.join(rootDir, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return undefined;
  }

  let parsed: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    parsed = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as typeof parsed;
  } catch {
    return undefined;
  }

  const range = parsed.devDependencies?.electron ?? parsed.dependencies?.electron;
  return range ? parseMajor(range) : undefined;
}

// Extracts the leading major number from a semver range. Accepts optional
// range operators (^ ~ >= <= > < =), whitespace, and a leading `v`, then
// requires digits followed by `.`, whitespace, or end-of-string — so
// "^43.1.0", ">= 20.0.0", "12", "v14.2" all parse, while "*", "latest",
// "next", and git URLs return undefined.
function parseMajor(range: string): number | undefined {
  const match = /^[\s^~>=<]*v?(\d+)(?:[.\s]|$)/.exec(range.trim());
  return match ? Number(match[1]) : undefined;
}
