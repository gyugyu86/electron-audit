# Changelog

## Unreleased

### Added

- `--version` (`-v`) flag that prints the tool's version and exits.

### Fixed

- A file that parses but throws during rule analysis (for example a
  same-scope duplicate binding that makes the AST scope-crawl throw) no
  longer aborts the whole scan. The offending file is skipped and the rest
  of the project is scanned. Skipped files are counted separately from parse
  failures and surfaced in the report; set `ELECTRON_AUDIT_DEBUG=1` to print
  the per-file error to stderr.
- `.ts` files that use TypeScript generics (`<T>`, generic arrow functions)
  are now parsed correctly. The parser previously enabled the JSX plugin for
  every extension, so a `.ts` generic's `<` was read as JSX, the file failed
  to parse, and it was silently skipped — a false negative if that file held
  a real issue. The JSX plugin is now selected by extension (`.ts`/`.mts`/
  `.cts` parse without it; `.tsx`/`.jsx`/`.js` keep it).

## 0.1.3

### Fixed

- EA040 no longer flags `shell.openExternal` calls that are already guarded
  by a scheme allowlist in the same function — the exact pattern the rule's
  own recommendation prescribes. The guard must dominate the call and check
  the same value the call receives; anything not statically provable still
  reports as before.
- `webPreferences` passed via a same-file helper function (e.g.
  `new BrowserWindow(getOptions())`) is now resolved statically instead of
  being reported as indeterminate. Only returns that are provably static are
  resolved; anything else keeps the previous heuristic reporting.

### Note

- No detection was weakened. A dangerous configuration resolved through the
  new path is reported at high confidence, not heuristic, exactly as an
  inline literal would be.
- No breaking changes.

### Packaging

- The build now removes `dist/` before compiling. tsc does not delete
  output files whose source moved or was deleted, so a stale artifact could
  otherwise linger into the packed tarball.
- `CHANGELOG.md` is included in the npm package.

### Internal

- Added a clean-app corpus harness (pinned upstream commit SHAs) that
  enforces zero high-confidence critical/high findings against known-safe
  Electron apps, run separately from the default test suite.

## 0.1.2

- Recommend pinning the GitHub Action by exact release tag (with an option
  to pin by commit SHA) instead of a moving major tag.

## 0.1.1

- Base SARIF result paths on the working directory instead of the scan
  target, so scanning a subdirectory still produces paths GitHub can match
  against the repository.

## 0.1.0

- Initial release.
