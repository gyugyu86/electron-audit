import { configDefaults, defineConfig } from 'vitest/config';

// The gitignored Tier-1 clean-corpus checkouts (tests/corpus/clean/.checkouts)
// are full third-party repos that ship their own test suites — vitest must
// never collect those. They are scanned only by scripts/checkCleanCorpus.ts
// via `npm run test:corpus:clean`. Everything else keeps vitest defaults.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, 'tests/corpus/clean/.checkouts/**'],
  },
});
