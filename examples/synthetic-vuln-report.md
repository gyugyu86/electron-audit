# electron-audit 리포트

**대상 프로젝트:** `tests/corpus/synthetic-vuln`

**요약:** 총 12건 — critical 5 · high 3 · medium 3 · info 1

_스캔한 파일 3개._

> `[heuristic]` 표시는 정적 분석만으로 확정할 수 없어 오탐 가능성이 있는 탐지입니다. 표시가 없으면 high-confidence(확실) 탐지입니다.

## 🔴 Critical (5)

### EA001 — new BrowserWindow({ webPreferences: { nodeIntegration: true } })

`main.js:16`

**왜 위험한가:** nodeIntegration: true exposes the full Node.js API (fs, child_process, require, etc.) directly to the renderer process. If the page the renderer loads runs attacker-controlled script — via XSS or similar — it immediately gains filesystem access and the ability to execute processes.

**권장 수정:**

```
Turn nodeIntegration off, and expose only the specific APIs you need through preload + contextBridge.

// main process
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});

// preload.js — expose only what's needed
contextBridge.exposeInMainWorld('api', {
  doSomething: () => ipcRenderer.invoke('do-something'),
});
```

### EA002 — contextIsolation: false

`main.js:16`

**왜 위험한가:** With contextIsolation off, the preload script and the renderer page share the same JS context. A malicious script on the page can hijack objects the preload exposed, or Electron internals, via prototype pollution and similar techniques, to escalate its privileges.

**권장 수정:**

```
Turn contextIsolation on (keep the default) and expose APIs from preload only through contextBridge.

const win = new BrowserWindow({
  webPreferences: {
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});
```

### EA020 — exec(`kill ${pid}`)

`main.js:57`

**왜 위험한가:** Interpolating or concatenating an externally-influenceable value directly into a shell command string lets an attacker inject shell metacharacters (semicolons, backticks, etc.) to run an unintended command alongside the intended one (command injection).

**권장 수정:**

```
Pass arguments as an array to execFile (or spawn with shell:false) instead of exec/execSync, so the value never goes through shell parsing.

// vulnerable
const { exec } = require('child_process');
exec(`kill ${pid}`);

// fixed — arguments split into an array, no shell involved
const { execFile } = require('child_process');
execFile('kill', [String(pid)]);
```

### EA021 — sudo.exec(`installer --source=${url}`, { name: 'SyntheticApp' }, () => {})

`main.js:63`

**왜 위험한가:** When a command-injection vulnerability is combined with a sudo-prompt-style privilege-escalation wrapper, the injected command runs with full administrator privileges once the user approves the prompt. If a value originating from the renderer or the network reaches this point, the entire system is compromised.

**권장 수정:**

```
Run only a fixed whitelist of commands where privilege escalation is needed, and pass arguments only after validating them.
sudo-prompt-style wrappers go through a shell internally, so never interpolate external input into the command string.

// vulnerable
sudo.exec(`some-tool --target=${url}`, options, callback);

// fixed — a fixed whitelisted command + validated arguments only
const ALLOWED_TARGETS = new Set(['a', 'b']);
if (!ALLOWED_TARGETS.has(target)) throw new Error('invalid target');
sudo.exec(`some-tool --target=${target}`, options, callback);
```

### EA020 — exec(`./run-installer.sh ${info.installerPath}`)

`updater.js:16`

**왜 위험한가:** Interpolating or concatenating an externally-influenceable value directly into a shell command string lets an attacker inject shell metacharacters (semicolons, backticks, etc.) to run an unintended command alongside the intended one (command injection).

**권장 수정:**

```
Pass arguments as an array to execFile (or spawn with shell:false) instead of exec/execSync, so the value never goes through shell parsing.

// vulnerable
const { exec } = require('child_process');
exec(`kill ${pid}`);

// fixed — arguments split into an array, no shell involved
const { execFile } = require('child_process');
execFile('kill', [String(pid)]);
```

## 🟠 High (3)

### EA006 — This window is configured dangerously, while another window in the same project is configured safely

`main.js:16`

**왜 위험한가:** One window in this project is configured safely (contextIsolation on / nodeIntegration off) while another is configured dangerously. This usually happens when a team hardens the main window but forgets a child window's (e.g. an "open-win"-style) webPreferences — and an attacker goes after whichever window has the weaker defenses. This was the actual vulnerable pattern in dnsChanger.

**권장 수정:**

```
Apply the same safe settings everywhere you create a BrowserWindow. Managing webPreferences through one shared factory prevents any single window from being missed.

function createSecureWindow(opts) {
  return new BrowserWindow({
    ...opts,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      ...opts.webPreferences,
    },
  });
}
```

### EA011 — script-src has 'unsafe-inline', 'unsafe-eval'

`main.js:49`

**왜 위험한가:** 'unsafe-inline' or 'unsafe-eval' in a CSP allows inline script/style or eval-family execution. unsafe-inline in a script-execution directive (script-src/default-src), and unsafe-eval anywhere, are an XSS-to-code-execution path and are reported at high; unsafe-inline in other directives (style-src, etc.) has a more limited attack surface and is reported at medium.

**권장 수정:**

```
Remove 'unsafe-inline'/'unsafe-eval', and allow specific inline content individually via a nonce or hash instead.

// vulnerable
"script-src 'self' 'unsafe-inline' 'unsafe-eval'"

// fixed
"script-src 'self' 'nonce-<generated-per-request>'"
```

### EA040 — shell.openExternal(<variable/expression>) `[heuristic]`

`main.js:68`

**왜 위험한가:** A value that can't be statically determined is passed to shell.openExternal. Without a scheme allowlist, an arbitrary URL could be opened, letting a dangerous scheme — file: (local file access) or javascript:/data: (code execution) — be injected via external input.

**권장 수정:**

```
Allowlist the scheme to https/http (and mailto if needed) before opening.

// vulnerable
shell.openExternal(url);

// fixed — only a safe scheme gets through
function openSafely(url) {
  const { protocol } = new URL(url);
  if (protocol === 'https:' || protocol === 'http:') {
    shell.openExternal(url);
  }
}
```

## 🟡 Medium (3)

### EA041 — setWindowOpenHandler is missing (a window that is not clearly safe exists) `[heuristic]`

`main.js:16`

**왜 위험한가:** A project whose windows aren't otherwise locked down has no setWindowOpenHandler at all. With nothing controlling new-window requests, an arbitrary URL could be opened via window.open and similar APIs. (Reported as heuristic since we can't statically confirm whether a real window-opening code path even exists.)

**권장 수정:**

```
Attach setWindowOpenHandler to every window, and only allow a URL to open after explicitly validating it.

win.webContents.setWindowOpenHandler(({ url }) => {
  if (isAllowed(url)) {
    return { action: 'allow' };
  }
  return { action: 'deny' };
});
```

### EA050 — Deserialized untrusted data (possibly remote) reaches a shell command unvalidated `[heuristic]`

`updater.js:16`

**왜 위험한가:** A value deserialized via JSON.parse or similar — one that can't be statically guaranteed trustworthy (it could be a remote response) — reaches a shell command unvalidated. If this value is attacker-controlled, it leads to command injection.

**권장 수정:**

```
Validate or allowlist the value before it reaches the sink, and use execFile + an argument array instead of a shell.

const ALLOWED = new Set(['a', 'b']);
if (!ALLOWED.has(info.action)) throw new Error('invalid');
execFile('tool', ['--action', info.action]);
```

### EA012 — default-src has a wildcard `*`

`main.js:49`

**왜 위험한가:** A CSP directive whose source is a bare wildcard `*` allows every origin — no different in practice from having no CSP at all. Arbitrary remote scripts or resources can be loaded.

**권장 수정:**

```
List only the origins you actually need instead of `*`. If you need subdomains, pin the domain like `*.example.com`.

// vulnerable
"default-src *"

// fixed
"default-src 'self' https://api.example.com"
```

## ⚪ Info (1)

### EA062 — electron 31.x (9 majors behind our baseline of 40.x) `[heuristic]`

`package.json:0`

**왜 위험한가:** Electron generally only ships security patches for roughly the latest 3 majors. A version significantly further behind than that may still carry known, unpatched Chromium/Node.js vulnerabilities. (The baseline 'latest' version is hardcoded in this tool and can lag behind the real latest, so verify the actual current version yourself.)

**권장 수정:**

```
Upgrade the electron dependency to the latest stable major, and check the release notes for compatibility changes.

// package.json
"devDependencies": {
  "electron": "^<latest-major>.0.0"
}
```

