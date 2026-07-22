# Clean corpus

Measures over-reporting: "would electron-audit break a known-good app's CI?"
Two layers:

- **Vendored** (`minimal-repro/`, provenance in `PROVENANCE.md`) — offline,
  runs inside `npm test` (`tests/corpus/cleanCorpus.test.ts`).
- **Tier-1 checkouts** (`tier1.json` → `.checkouts/`, gitignored) — full
  third-party repos fetched by `npm run corpus:fetch` and gated by
  `npm run test:corpus:clean` (CI: the `clean-corpus` workflow). Pinned to
  exact commit SHAs so upstream movement can never change results.

## Gate

A finding fails the gate iff the tool's own default exit-code policy would
fail on it: **high-confidence AND severity critical/high** — classified by
running each finding through `cli/exitCode.ts`, so the gate can never drift
from what `electron-audit` itself fails a consumer's build on. Heuristic
findings and high-confidence medium/low/info findings are allowed.

## Tier-1 pins and findings distribution

**Reference only.** This table exists so a human can eyeball what changed
after a rule edit or a SHA bump; it is deliberately **not** a test snapshot.
The gate above is the only enforced criterion — a full-distribution snapshot
could not distinguish "new false positive" (bad) from "rule improvement
reduced findings" (good), and would get blindly `-u`-refreshed on every
upstream bump.

| repo | pinned SHA | findings at this SHA |
| :-- | :-- | :-- |
| electron/fiddle | `75831f72ca4b1345fd73622be814d12393386a2a` | 10 — EA011×2 (own HTML CSP `style-src 'unsafe-inline'`, medium), EA042×5 (all in the bundled `static/show-me/` example apps), EA060×3 (Sentry, info). The `webPreferences` call site `src/main/windows.ts:74` (`new BrowserWindow(getMainWindowOptions())`) no longer fans out to EA001/002/003/004/005/007 — the helper's returned config is now resolved statically and is safe. |
| electron/minimal-repro | `b4f681add21303def253f4f1a36cfe28d44787fe` | 1 — EA011×1 (own CSP `style-src 'unsafe-inline'`, medium) |

High-confidence critical/high on both: **0**.

Operational rule: when bumping a pin in `tier1.json`, re-run
`npm run corpus:fetch && npm run test:corpus:clean` and update this table in
the same commit.
