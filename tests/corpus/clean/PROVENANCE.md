# Clean corpus — provenance

The subdirectories here are **vendored third-party code**, not part of
electron-audit. They exist so the false-positive test
(`tests/corpus/cleanCorpus.test.ts`) can assert that a correctly-written,
genuinely-safe Electron app produces **zero** findings under the full
`ALL_RULES` set — the only way to measure the spec M3 "no false positives"
bar against code we didn't write.

Vendored via abridged copy (only the files needed for the fixture), so the
test corpus is reproducible offline with no network fetch in CI.

## minimal-repro/

- Source: <https://github.com/electron/minimal-repro>
  (upstream renamed the repo from `electron-quick-start`; this snapshot was
  taken under the old name — same repo, the old URL redirects)
- Commit: `b4f681add21303def253f4f1a36cfe28d44787fe`
- License: **CC0-1.0** (public-domain dedication — see
  `minimal-repro/LICENSE.md`).
  - Note: this was requested as "MIT", but the upstream repo is actually
    licensed CC0-1.0. CC0 is strictly more permissive than MIT, so
    vendoring is fine; recording the true license here for accuracy.
- Files copied: `main.js`, `preload.js`, `renderer.js` (the scannable JS),
  plus `package.json` (its `main` field lets the file-role classifier run
  against real input), `LICENSE.md`, and `index.html`.
- The `.js` files and `index.html` each carry a provenance header comment;
  that header is the only modification to the upstream bodies.
  `package.json` and `LICENSE.md` are byte-identical to upstream (JSON/
  plain-text can't carry a comment), and their provenance is recorded here.
- `index.html` is **not scanned** (the tool reads only JS/TS). It's vendored
  purely to document that this app sets its CSP in a
  `<meta http-equiv="Content-Security-Policy">` tag — which a JS-only scanner
  cannot see. That blind spot is exactly why EA010 (CSP absence) fires a
  **heuristic** on this app, and why the clean-corpus test's bar is
  "no high-confidence findings" rather than "no findings at all". (The meta
  CSP itself contains `style-src 'self' 'unsafe-inline'`, which likewise is
  out of scope for EA011 — HTML isn't parsed.)
- Not copied: `styles.css`, `package-lock.json`, `.github/`, `README.md` —
  not needed for the fixture.
