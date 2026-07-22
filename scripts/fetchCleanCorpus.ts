// Fetches the Tier-1 clean-corpus checkouts listed in
// tests/corpus/clean/tier1.json into the gitignored checkouts directory.
// Each checkout is pinned to an exact commit SHA (shallow fetch of that one
// commit), so results are reproducible regardless of upstream movement.
// Fails loudly on any network/git error — in CI this step failing is the
// signal, and the gate script never runs against a half-fetched tree.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

interface Tier1Checkout {
  name: string;
  url: string;
  sha: string;
  license: string;
}
interface Tier1Config {
  checkoutsDir: string;
  checkouts: Tier1Checkout[];
}

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(
  readFileSync(path.join(rootDir, 'tests/corpus/clean/tier1.json'), 'utf8'),
) as Tier1Config;

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

for (const { name, url, sha } of config.checkouts) {
  const dir = path.join(rootDir, config.checkoutsDir, name);
  try {
    if (existsSync(path.join(dir, '.git'))) {
      if (git(dir, 'rev-parse', 'HEAD') === sha) {
        console.log(`${name}: already at ${sha.slice(0, 7)} (cached)`);
        continue;
      }
      console.log(`${name}: re-pinning to ${sha.slice(0, 7)}`);
      git(dir, 'fetch', '--quiet', '--depth', '1', 'origin', sha);
      git(dir, 'checkout', '--quiet', '--detach', sha);
    } else {
      console.log(`${name}: cloning ${url} @ ${sha.slice(0, 7)} (shallow, pinned)`);
      mkdirSync(dir, { recursive: true });
      git(dir, 'init', '--quiet');
      git(dir, 'remote', 'add', 'origin', url);
      git(dir, 'fetch', '--quiet', '--depth', '1', 'origin', sha);
      git(dir, 'checkout', '--quiet', '--detach', 'FETCH_HEAD');
    }
    const head = git(dir, 'rev-parse', 'HEAD');
    if (head !== sha) {
      console.error(`${name}: HEAD ${head} does not match the pinned ${sha}`);
      process.exit(1);
    }
    console.log(`${name}: ready at ${sha.slice(0, 7)}`);
  } catch (error) {
    console.error(`${name}: fetch failed — ${(error as Error).message}`);
    process.exit(1);
  }
}
