import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { readPackageVersion } from '../../src/cli/version.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const packageJson = JSON.parse(
  readFileSync(path.join(dirname, '../../package.json'), 'utf8'),
) as { version: string };

describe('readPackageVersion', () => {
  // Guards against the version being hardcoded and drifting from package.json:
  // this reads the manifest independently and must match what the CLI reports.
  it("returns package.json's version verbatim", () => {
    expect(readPackageVersion()).toBe(packageJson.version);
  });

  it('returns a semver-shaped string', () => {
    expect(readPackageVersion()).toMatch(/^\d+\.\d+\.\d+/);
  });
});
