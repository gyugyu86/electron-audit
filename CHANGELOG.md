# Changelog

## Unreleased

### Fixed

- A privileged command execution (`sudo-prompt` and its forks) whose command
  string is assembled rather than written inline is now reported as EA021
  (critical, heuristic) instead of falling into the generic EA022. Whether a
  call runs as root is a severity fact; whether its argument is statically
  provable is a confidence fact, and the two are separate fields — but the
  order of the checks let the confidence judgment discard the severity one, so
  the report stopped mentioning privilege escalation at all. `sudo.exec(cmd, …)`
  and `sudo.exec(parts.join(' '), …)` are the common shapes in real code, so
  this was the usual outcome rather than an edge case.
- No new findings are produced: the classification of findings that were
  already reported changes, and detection criteria are untouched. Exit codes
  are unaffected in every mode — these findings are heuristic, so the default
  gate still ignores them, and `--strict` already failed on them at their
  previous severity.

## 0.1.5 - 2026-07-26

### Fixed

- Files using decorators (`@Entity()`, `@Column()`, and the parameter
  decorators Angular/NestJS/TypeORM dependency injection relies on) are now
  parsed instead of being skipped whole. The parser enabled no decorator
  plugin, so every such file failed to parse and no rule ever saw it — a
  silent false negative. The two decorator dialects are mutually exclusive in
  the parser and neither is a superset of the other, so a file that needs one
  is retried with each; the retry is gated to failures the parser reports as a
  missing decorator plugin, leaving ordinary syntax errors and deeply-nested
  input to fail once as before.

### Note

- Because this recovers files that were previously invisible, a project using
  decorators may see findings it did not see before. If any of them are
  high-confidence at critical/high severity, the default exit code will now
  fail a build that used to pass. Those files were never scanned before — the
  issues are not new, only newly visible. If new findings land mid-sprint,
  `--no-fail` lets CI stay green while you triage them — the findings still
  appear in the report.

## 0.1.4 - 2026-07-23

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
- Built-in module imports written with the `node:` protocol prefix (e.g.
  `import { exec } from 'node:child_process'`, `require('node:fs')`) are now
  recognized the same as the un-prefixed spelling. The command-injection and
  file-path-sink rules matched only the bare name before, so a modern
  codebase using `node:` was missed. The prefix is normalized in one place
  where import/require sources are collected, so all built-in matching is
  consistent.

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
