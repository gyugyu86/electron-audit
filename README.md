# electron-audit

[한국어 README](https://github.com/gyugyu86/electron-audit/blob/main/README.ko.md)

**A CLI that statically analyzes Electron apps for security anti-patterns** —
low false positives, dataflow-aware, and current with modern Electron.

[![npm](https://img.shields.io/npm/v/electron-audit.svg)](https://www.npmjs.com/package/electron-audit)
[![license](https://img.shields.io/npm/l/electron-audit.svg)](https://github.com/gyugyu86/electron-audit/blob/main/LICENSE)
[![CI](https://github.com/gyugyu86/electron-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/gyugyu86/electron-audit/actions/workflows/ci.yml)

Point it at an Electron project and it reads the main process, preload,
renderer, and config files to find the mistakes Electron apps make over and
over — Node exposed to the renderer, weak CSPs, command injection, unvalidated
external URLs and remote data — then reports them by severity. It never runs
your app; it only parses the source, so it's fast, safe, and easy to drop into
CI.

---

## Why this tool

Electron security linting isn't new. [Electronegativity](https://github.com/doyensec/electronegativity)
opened this space and is still worth knowing. But the free open-source version
has stalled — its latest release is **v1.10.3 (March 2023), and it doesn't
recognize recent Electron versions** (it prints `Unknown Electron release` at
runtime). Electron's own docs still point to it. electron-audit is **not a
replacement — it picks up where that left off.** Electronegativity has broader
coverage (it inspects HTML/DOM too); electron-audit's focus is not breadth but
three things:

- **Low false positives.** Every finding carries a `confidence` (high /
  heuristic) *separate* from its severity, so "certain" and "suspected" are
  never conflated. And a regression test **enforces zero high-confidence false
  positives** against a corpus of real, correctly-written apps.
- **Dataflow awareness.** Beyond pattern matching, it approximates whether
  untrusted input (deserialized data, network responses, IPC arguments) flows
  into a dangerous sink (command execution, file paths, external URLs) — a
  source-to-sink notion the free prior art doesn't have.
- **Modern Electron + CI-friendly.** It knows current versions, emits SARIF for
  GitHub code scanning, and has a low-false-positive exit-code policy that fits
  CI cleanly.

## Real-world validation

Instead of claims, it was validated against real public apps — with the
**misses recorded honestly**. (Scope is "in the apps we tested," not "perfect
everywhere.")

- On **[dnsChanger-desktop](https://github.com/DnsChanger/dnsChanger-desktop)**
  (a real app) it flags a privilege-escalation command-injection RCE
  (`sudo.exec` with a store value interpolated in) at high confidence — a spot
  the prior tool misses — and catches the vulnerable HTML `<meta>` CSP.
  → [validation-dnschanger.md](https://github.com/gyugyu86/electron-audit/blob/main/examples/validation-dnschanger.md)
- Across **four apps of different character** (dnsChanger / zonote / Notable /
  minimal-repro — formerly electron-quick-start): **zero high-confidence false positives**, and the large
  app scanned to completion without a crash — evidence that FP=0 generalizes
  rather than being specific to one app.
  → [validation-overfitting.md](https://github.com/gyugyu86/electron-audit/blob/main/examples/validation-overfitting.md)

## Install & quick start

```bash
# no install
npx electron-audit <path-to-electron-project>

# or install globally
npm install -g electron-audit
electron-audit <path-to-electron-project>
```

Terminal output (on a deliberately-vulnerable sample project):

```
main.js:16
   CRITICAL  EA001  new BrowserWindow({ webPreferences: { nodeIntegration: true } })
     Why it's dangerous: nodeIntegration: true exposes the full Node.js API to the renderer ...
     Recommended fix:
       nodeIntegration: false + preload/contextBridge ...
   CRITICAL  EA002  contextIsolation: false
   HIGH      EA006  this window is unsafe while another window in the project is safe
updater.js:16
   CRITICAL  EA020  exec(`./run-installer.sh ${info.installerPath}`)
   MEDIUM  [heuristic] EA050  deserialized untrusted data reaches a shell command unvalidated
...
12 findings (critical 5 · high 3 · medium 3 · info 1)
```

Full sample reports:
[Markdown](https://github.com/gyugyu86/electron-audit/blob/main/examples/synthetic-vuln-report.md) ·
[JSON](https://github.com/gyugyu86/electron-audit/blob/main/examples/synthetic-vuln-report.json) ·
[SARIF](https://github.com/gyugyu86/electron-audit/blob/main/examples/dnschanger.sarif)

## Usage

```bash
electron-audit <path>              # terminal report (default)
electron-audit <path> --json       # structured JSON (for downstream tools)
electron-audit <path> --markdown   # human-readable Markdown report
electron-audit <path> --sarif      # SARIF 2.1.0 (GitHub code scanning)
electron-audit <path> --config <file>   # enable/disable rules, override severity
```

### Confidence: certain vs heuristic

Every finding carries a confidence *separate* from severity. No `[heuristic]`
tag means a statically-unambiguous, high-confidence finding; the tag means an
approximation (dataflow, version-dependent judgment) that may be a false
positive. This split is the tool's reliability contract.

### Config file (`--config`)

Disable rules or change their severity (JSON, or JS with `export default`). A
bad config produces a friendly error, not a crash.

```json
{ "ruleOverrides": { "EA062": { "enabled": false }, "EA042": { "severity": "low" } } }
```

### Exit codes (CI gate)

The low-false-positive philosophy extends to the exit code — **a tool that
fails your build on its own false positives is one nobody keeps in CI.**

| Mode | Exits 1 (fails) when |
| :-- | :-- |
| default | there is any **high-confidence** finding at severity **critical/high** |
| `--strict` | the above, plus heuristic findings at severity critical/high |
| `--no-fail` | never (report only, always exits 0) |

By default, heuristic / info / low / medium findings never break the build.

## GitHub Action (code scanning)

Upload `--sarif` results to GitHub code scanning and findings appear in the
**Security tab and as PR annotations**.

```yaml
# .github/workflows/electron-audit.yml
name: electron-audit
on:
  push:
  pull_request:
permissions:
  contents: read
  security-events: write   # required to upload SARIF
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gyugyu86/electron-audit@v0.1.2
        with:
          path: .                  # project to scan
          version: 0.1.2           # pin the scanner (default: latest)
          # fail-on-findings: true # fail on high-confidence critical/high (default)
          # upload: true           # upload to code scanning (default)
```

`@v0.1.2` is the recommended pin. For the strongest supply-chain guarantee, pin
the commit SHA the tag resolves to instead — an author can move a tag, but not a
commit SHA. Run `git rev-parse v0.1.2^{commit}` and use
`uses: gyugyu86/electron-audit@<sha>  # v0.1.2`.

The SARIF is uploaded even when there are findings (the gate is a separate
step); set `fail-on-findings: false` to report only. GitHub runners ship with
Node, so no setup step is needed.

On pull requests **from a fork**, GitHub withholds `security-events: write`, so
the upload step is skipped there — a GitHub restriction, not an error. Runs on
branches in the same repository upload normally.

## Rules (21 implemented)

Severity: `critical` > `high` > `medium` > `low` > `info`.

| ID | Group | Severity | Detects |
| :-- | :-- | :-- | :-- |
| EA001 | A. webPreferences | critical | `nodeIntegration: true` — Node API exposed to the renderer |
| EA002 | A | critical | `contextIsolation: false` (or an unsafe old-version default) |
| EA003 | A | high | `sandbox` unset/`false` |
| EA004 | A | high | `webSecurity: false` |
| EA005 | A | medium | `allowRunningInsecureContent: true` |
| EA006 | A | high | inconsistent `webPreferences` across windows (a safe window next to an unsafe one) |
| EA007 | A | high/info | `enableRemoteModule: true` (info on Electron 14+, where it was removed) |
| EA010 | B. CSP | high | no CSP found (in JS or HTML `<meta>`, heuristic) |
| EA011 | B | high/medium | CSP `unsafe-inline`/`unsafe-eval` (high for script-src·eval) |
| EA012 | B | medium | wildcard `*` CSP source (partial wildcards excluded) |
| EA013 | B | info | Cordova leftovers (`gap:`) and other pasted-CSP signatures |
| EA020 | C. command execution | critical | interpolated command string in `exec`/`spawn(shell:true)` |
| EA021 | C | critical | the above combined with a `sudo-prompt`-style privilege escalator |
| EA022 | C | high | an unvalidated variable reaching a shell (heuristic) |
| EA040 | E. external interaction | high | `shell.openExternal(variable)` — no scheme allowlist |
| EA041 | E | medium | missing `setWindowOpenHandler`, or one that unconditionally allows |
| EA042 | E | medium | `loadURL` with a remote/non-https literal URL |
| EA050 | F. remote data | medium | untrusted deserialized/external input reaching a dangerous sink unvalidated (heuristic) |
| EA060 | G. hygiene | info | analytics/telemetry SDK (privacy notice) |
| EA061 | G | low | no electron-builder code-signing config |
| EA062 | G | info | Electron version far behind the latest |

## Honest limitations

As a static analyzer that only parses JS/TS, there are things it **deliberately
doesn't catch** — it accepts false negatives to avoid false positives. That's
not a weakness; it's the condition for trust.

- **HTML is only read shallowly for `<meta>` CSP.** It extracts the CSP string
  from `<meta http-equiv="Content-Security-Policy">` via regex and runs
  EA010/011/012 on it (so CSP in both JS and HTML is covered), but this is not
  full HTML/DOM parsing — `<webview>` attributes, `will-navigate`, etc. are not
  covered (v2).
- **Dataflow is approximated within a single function scope.** EA050 only
  connects a source to a sink when they're directly wired in the same function;
  flows across function boundaries, return values, and reassignment aren't
  traced.
- **Known misses** (self-found during the overfitting check): a `data:` URL
  `loadURL` with interpolated HTML (an XSS vector), and dynamically
  merged/spread `webPreferences` (under-reported as heuristic).
- **The version baseline is hardcoded** (EA062): for offline/CI reproducibility,
  the "latest Electron" baseline lives in the source, so it goes stale over time
  (hence heuristic). Updating it is a one-line constant change.
- **No runtime behavior** — the general limit of static analysis.

Deferred rules: **EA043** (will-navigate/webview — needs full HTML parsing) and
**EA051** (electron-updater signature verification — a real known RCE class, but
a low-false-positive static signal isn't available yet). Held for v2 rather than
shipped as noise.

## Roadmap (v1.1+)

Concrete material that came out of the overfitting check:

- Resolve dynamically merged/spread `webPreferences` (currently under-reported
  as heuristic).
- Cover the `data:` URL `loadURL` (interpolated HTML) miss.
- Recognize a scheme guard around `openExternal` to cut heuristic noise.
- EA043 (webview) — alongside full HTML parsing.
- EA051 (electron-updater signature verification) — once a low-FP signal exists.

1.0 focuses on stabilizing the interface based on early user feedback.

## Development / contributing

```bash
npm install
npm run build   # tsc
npm test        # vitest (rule units + corpus regression + robustness + FP=0)
npm run lint    # eslint
npm run dev -- <path>   # run locally
```

See [docs/ARCHITECTURE.md](https://github.com/gyugyu86/electron-audit/blob/main/docs/ARCHITECTURE.md)
for architecture and rule-authoring conventions. Core principles: the analysis
engine (`src/core`) knows nothing about the CLI, one file per rule, and every
new rule ships with vulnerable/safe fixtures and unit tests.

## The tool's own security

electron-audit **never executes the code it analyzes** — it only parses it. When
it does spawn a process, it uses `execFile` with an argument array (no shell
interpolation). Robustness against untrusted input (huge/broken/malicious files,
symlink escapes) is pinned by tests.

## License

[MIT](https://github.com/gyugyu86/electron-audit/blob/main/LICENSE)
