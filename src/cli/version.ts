import { readFileSync } from 'node:fs';

// The tool's own version, read from its package.json rather than hardcoded so
// there is only one place a release bump has to touch. `../../package.json` is
// the package root two levels up from this module in every layout it runs in:
// dev via tsx (src/cli/version.ts) and the built/installed output
// (dist/cli/version.js -> dist -> package root). Falls back to '0.0.0' if the
// manifest can't be read, so a packaging accident degrades instead of crashing.
export function readPackageVersion(): string {
  try {
    const pkgUrl = new URL('../../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgUrl, 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}
