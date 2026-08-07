# Changelog

## 0.1.9 - 2026-08-06

### Changed

- More findings now report which kind of file they sit in. Two things were
  keeping the answer unknown. A manifest that names a bundler output rather
  than a source file said nothing about where the code lives, and in a
  workspace the manifest that names the entry point is not the one at the
  root — so entry points declared by any package.json in the project are now
  read, at any depth. Where nothing declares a file, the directory a project
  keeps its processes in (`main/`, `preload/`, `renderer/`) is used instead.
  Measured across the projects tested, roughly a quarter of findings carried a
  role before and closer to half do now.
- **The order of those signals is what keeps them honest.** A declared entry
  point wins over everything, then the filename, then build tooling, and the
  directory name is asked last, only when nothing more certain has answered.
  A directory called `main` does not always mean the main process — in a real
  app measured during this work, `windows/main/` is the main *window*, sibling
  to `windows/about/` and `windows/loading/`, and holds preload code. The
  filename settles those before the directory is consulted.
- Findings whose role still cannot be determined continue to show no role
  rather than a guess, as in 0.1.8.

### Note

- **Severity, confidence and exit codes are unchanged.** This affects which
  findings can say what kind of file they are in, nothing about how they are
  judged — verified against the published build across nine projects in all
  three exit modes, with identical exit codes and identical finding counts.

## 0.1.8 - 2026-08-06

### Added

- A finding can now report the kind of file it sits in — `main`, `preload` or
  the new `build`, which marks build, packaging and code-signing tooling. The
  scanner had always classified files and nothing ever read the result.
- The point is that a finding in a signing script and a finding in the running
  app read differently. The first sits in the build and release path, with its
  input controlled by the build environment; the second is exposed to whoever
  uses the app. 0.1.7 started surfacing the first kind in numbers and left you
  to tell them apart by reading paths.
- **The role appears only when it was actually determined.** No role shown
  means the tool could not tell, not that the file is unimportant — roughly
  seven findings in ten across the projects measured. The classifier's
  fallback answer is `renderer`, so reporting it would have printed
  "renderer" wherever nothing matched, including on files whose own path
  reads `src/main/`. The contract is the useful direction: **when a role is
  shown, it is known.**

### Note

- **Nothing about how findings are judged changes.** Severity, confidence and
  the exit code are exactly as before — this adds a label, not a verdict. A
  build-time finding still fails the build under the default gate if it is
  high-confidence at critical/high severity, because a shell command assembled
  from an interpolated path is a real risk wherever it runs. Verified across
  eight projects in all three exit modes, with identical exit codes and
  identical finding counts.
- Withholding an uncertain role is deliberately not the same as lowering
  `confidence`. `confidence` says how sure the tool is that the code is
  dangerous; how sure it is about which process a file runs in is a separate
  question, and letting a path heuristic answer the first would weaken a real
  security verdict.
- The classification is conservative in the same spirit, and never overrides a
  fact about how the app runs: a file the manifest names as the entry point
  stays `main`, and a build-looking name inside an application source tree
  stays application code. Unrecognized build tooling reports no role rather
  than a guessed one.
- **This does change the output format.** JSON findings gain an optional
  `role` key, and SARIF results carry `role` in the result property bag
  alongside `confidence`. The key is omitted, not null, when a finding has no
  role — either because the role could not be determined, or because the
  finding is anchored on `.html` (the CSP rules) or on package.json
  (EA060/EA061/EA062), neither of which is a scanned source file.
  `schemaVersion` stays `1`: adding an optional key is not a breaking change,
  and existing consumers that read known keys are unaffected.

## 0.1.7 - 2026-07-30

### Fixed

- `.mjs`, `.cjs`, `.mts` and `.cts` files are now scanned. The file collector
  accepted only `.js`/`.ts`/`.jsx`/`.tsx`, so every other module extension was
  dropped before it ever reached the parser — **no rule has ever seen those
  files** — and the omission was invisible in the report's unparsable and
  analysis-error counts alike, because a file that is never opened cannot fail
  to parse. Electron projects keep build, packaging and code-signing scripts in
  exactly those files, and assembling a shell command from an interpolated path
  is common there, so this hid real findings behind a silent zero. They are the
  same JavaScript and TypeScript the analyzer already handles — only the module
  system differs — so no rule needed changing; `.mts`/`.cts` parse as
  TypeScript with JSX off, matching `.ts`.

### Note

- Unlike 0.1.6, this adds files to the scan rather than reclassifying findings
  that were already reported, so a project containing any of these extensions
  can see findings it did not see before, and a build that passed under the
  default exit code can now fail. Those files were never scanned before — the
  issues are not new, only newly visible. If new findings land mid-sprint,
  `--no-fail` lets CI stay green while you triage them; the findings still
  appear in the report.
- **Expect build tooling to be where they show up.** More than half of the
  newly collected files are build, packaging and signing scripts rather than
  application code, and that is where a shell command assembled from an
  interpolated path is most common — so a new critical/high finding is more
  likely to point at a signing script than at your app's runtime. The rule is
  correct to fire; assembling a shell command that way is a real risk. But the
  exposure differs in kind from runtime code — it sits in the build and release
  path, and the input is controlled by the build environment rather than an end
  user — and the report does not yet make that distinction.
- `.vue` and `.svelte` remain out of scope. Their JavaScript lives inside a
  `<script>` block that has to be extracted before anything can parse it,
  which is a separate feature rather than another extension.

## 0.1.6 - 2026-07-29

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
