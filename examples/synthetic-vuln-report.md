# electron-audit 리포트

**대상 프로젝트:** `tests/corpus/synthetic-vuln`

**요약:** 총 12건 — critical 5 · high 3 · medium 3 · info 1

_스캔한 파일 3개._

> `[heuristic]` 표시는 정적 분석만으로 확정할 수 없어 오탐 가능성이 있는 탐지입니다. 표시가 없으면 high-confidence(확실) 탐지입니다.

## 🔴 Critical (5)

### EA001 — new BrowserWindow({ webPreferences: { nodeIntegration: true } })

`main.js:16`

**왜 위험한가:** nodeIntegration: true는 렌더러 프로세스에 Node.js API(fs, child_process, require 등)를 그대로 노출합니다. 렌더러가 로드하는 페이지에서 XSS 등으로 임의 스크립트가 실행되면 그 즉시 파일시스템 접근·프로세스 실행 권한까지 함께 탈취됩니다.

**권장 수정:**

```
nodeIntegration을 끄고, preload + contextBridge로 필요한 API만 선택적으로 노출하세요.

// 메인 프로세스
const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});

// preload.js — 필요한 기능만 골라서 노출
contextBridge.exposeInMainWorld('api', {
  doSomething: () => ipcRenderer.invoke('do-something'),
});
```

### EA002 — contextIsolation: false

`main.js:16`

**왜 위험한가:** contextIsolation이 꺼져 있으면 preload 스크립트와 렌더러 페이지가 같은 JS 컨텍스트를 공유합니다. 페이지의 악성 스크립트가 preload가 노출한 객체나 Electron 내부 API를 프로토타입 오염 등으로 탈취해 권한을 확대할 수 있습니다.

**권장 수정:**

```
contextIsolation을 켜고(기본값 유지) preload에서는 contextBridge로만 API를 노출하세요.

const win = new BrowserWindow({
  webPreferences: {
    contextIsolation: true,
    preload: path.join(__dirname, 'preload.js'),
  },
});
```

### EA020 — exec(`kill ${pid}`)

`main.js:57`

**왜 위험한가:** 셸 명령 문자열에 외부 영향을 받을 수 있는 값을 템플릿 보간이나 문자열 연결로 직접 끼워 넣으면, 공격자가 세미콜론·백틱 등 셸 메타문자를 주입해 의도하지 않은 명령을 함께 실행시킬 수 있습니다(명령 주입).

**권장 수정:**

```
exec/execSync 대신 execFile(또는 shell:false spawn)에 인자를 배열로 넘겨, 값이 셸 파싱을 거치지 않게 하세요.

// 취약
const { exec } = require('child_process');
exec(`kill ${pid}`);

// 수정 — 인자를 배열로 분리, 셸을 거치지 않음
const { execFile } = require('child_process');
execFile('kill', [String(pid)]);
```

### EA021 — sudo.exec(`installer --source=${url}`, { name: 'SyntheticApp' }, () => {})

`main.js:63`

**왜 위험한가:** 명령 주입 취약점이 sudo-prompt류 권한상승 래퍼와 결합되면, 주입된 명령이 사용자 승인 절차를 거쳐 그대로 관리자 권한으로 실행됩니다. 렌더러나 네트워크에서 흘러온 값이 여기까지 도달하면 시스템 전체가 장악됩니다.

**권장 수정:**

```
권한상승이 필요한 명령은 고정된 화이트리스트만 실행하고, 인자는 검증 후 값만 전달하세요.
sudo-prompt류는 내부적으로 셸을 거치므로 명령 문자열에 외부 입력을 절대 보간하지 마세요.

// 취약
sudo.exec(`some-tool --target=${url}`, options, callback);

// 수정 — 화이트리스트에 있는 고정 명령 + 검증된 인자만
const ALLOWED_TARGETS = new Set(['a', 'b']);
if (!ALLOWED_TARGETS.has(target)) throw new Error('invalid target');
sudo.exec(`some-tool --target=${target}`, options, callback);
```

### EA020 — exec(`./run-installer.sh ${info.installerPath}`)

`updater.js:16`

**왜 위험한가:** 셸 명령 문자열에 외부 영향을 받을 수 있는 값을 템플릿 보간이나 문자열 연결로 직접 끼워 넣으면, 공격자가 세미콜론·백틱 등 셸 메타문자를 주입해 의도하지 않은 명령을 함께 실행시킬 수 있습니다(명령 주입).

**권장 수정:**

```
exec/execSync 대신 execFile(또는 shell:false spawn)에 인자를 배열로 넘겨, 값이 셸 파싱을 거치지 않게 하세요.

// 취약
const { exec } = require('child_process');
exec(`kill ${pid}`);

// 수정 — 인자를 배열로 분리, 셸을 거치지 않음
const { execFile } = require('child_process');
execFile('kill', [String(pid)]);
```

## 🟠 High (3)

### EA006 — 이 창은 위험하게 설정됐으나 같은 프로젝트의 다른 창은 안전하게 설정됨

`main.js:16`

**왜 위험한가:** 같은 프로젝트 안에서 어떤 창은 안전하게(contextIsolation on / nodeIntegration off) 설정됐는데 다른 창은 위험하게 설정돼 있습니다. 보통 메인 창만 신경 쓰고 자식 창(예: open-win 류)의 webPreferences를 빠뜨린 실수로, 공격자는 방어가 약한 창을 노립니다. dnsChanger의 실제 취약 패턴이 이것이었습니다.

**권장 수정:**

```
모든 BrowserWindow 생성 지점에 동일한 안전 설정을 적용하세요. 공용 팩토리로 webPreferences를 한 곳에서 관리하면 창마다 빠뜨리는 실수를 막을 수 있습니다.

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

### EA011 — script-src에 'unsafe-inline', 'unsafe-eval'

`main.js:49`

**왜 위험한가:** CSP에 'unsafe-inline' 또는 'unsafe-eval'이 있으면 인라인 스크립트/스타일이나 eval 계열 실행이 허용됩니다. 스크립트 실행 디렉티브(script-src/default-src)의 unsafe-inline·모든 unsafe-eval은 XSS→코드실행 경로라 high로, 그 외 디렉티브(style-src 등)의 unsafe-inline은 공격 표면이 제한적이라 medium으로 보고합니다.

**권장 수정:**

```
'unsafe-inline'/'unsafe-eval'을 제거하고, 필요한 인라인은 nonce나 hash로 개별 허용하세요.

// 취약
"script-src 'self' 'unsafe-inline' 'unsafe-eval'"

// 수정
"script-src 'self' 'nonce-<요청마다 생성한 값>'"
```

### EA040 — shell.openExternal(<변수/표현식>) `[heuristic]`

`main.js:68`

**왜 위험한가:** shell.openExternal에 정적으로 확정할 수 없는 값이 전달됩니다. 스킴 화이트리스트 없이 임의 URL이 열리면 file://(로컬 파일 접근)이나 javascript:/data:(코드 실행) 같은 위험한 스킴이 외부 입력으로 주입될 수 있습니다.

**권장 수정:**

```
열기 전에 스킴을 https/http(필요 시 mailto)로 화이트리스트 검증하세요.

// 취약
shell.openExternal(url);

// 수정 — 안전한 스킴만 통과
function openSafely(url) {
  const { protocol } = new URL(url);
  if (protocol === 'https:' || protocol === 'http:') {
    shell.openExternal(url);
  }
}
```

## 🟡 Medium (3)

### EA041 — setWindowOpenHandler 부재 (안전하게 설정되지 않은 창이 존재) `[heuristic]`

`main.js:16`

**왜 위험한가:** 창을 안전하게 잠그지 않은 프로젝트에 setWindowOpenHandler가 전혀 없습니다. 새 창 생성 요청을 통제하는 지점이 없으면 window.open 등으로 임의 URL이 열릴 수 있습니다. (정적으로 실제 창 열기 경로 유무까지는 확인할 수 없어 휴리스틱으로 보고합니다.)

**권장 수정:**

```
모든 창에 setWindowOpenHandler를 걸고, 허용할 URL을 명시적으로 검증한 뒤에만 열도록 하세요.

win.webContents.setWindowOpenHandler(({ url }) => {
  if (isAllowed(url)) {
    return { action: 'allow' };
  }
  return { action: 'deny' };
});
```

### EA050 — 역직렬화된 신뢰 불가 데이터(원격일 수 있음)가 검증 없이 셸 명령으로 흘러감 `[heuristic]`

`updater.js:16`

**왜 위험한가:** JSON.parse 등으로 역직렬화된, 정적으로 신뢰를 보장할 수 없는 값(원격 응답일 수 있음)이 검증 없이 셸 명령에 도달합니다. 이 값이 공격자 통제 하에 있으면 명령 주입으로 이어집니다.

**권장 수정:**

```
싱크에 넘기기 전에 값을 검증하거나 화이트리스트로 제한하고, 셸 대신 execFile + 인자 배열을 쓰세요.

const ALLOWED = new Set(['a', 'b']);
if (!ALLOWED.has(info.action)) throw new Error('invalid');
execFile('tool', ['--action', info.action]);
```

### EA012 — default-src에 와일드카드 `*`

`main.js:49`

**왜 위험한가:** CSP 디렉티브의 소스가 와일드카드 `*` 하나면 모든 오리진을 허용하는 것과 같아 CSP가 사실상 없는 것과 다르지 않습니다. 임의의 원격 스크립트/리소스가 로드될 수 있습니다.

**권장 수정:**

```
`*` 대신 실제로 필요한 오리진만 명시하세요. 서브도메인이 필요하면 `*.example.com`처럼 도메인을 고정하세요.

// 취약
"default-src *"

// 수정
"default-src 'self' https://api.example.com"
```

## ⚪ Info (1)

### EA062 — electron 31.x (기준 최신 40.x 대비 9 메이저 뒤처짐) `[heuristic]`

`package.json:0`

**왜 위험한가:** Electron은 대략 최신 3개 메이저 버전만 보안 패치를 제공합니다. 그보다 크게 뒤처진 버전은 Chromium·Node.js의 알려진 취약점이 수정되지 않은 채 남아 있을 수 있습니다. (기준 최신 버전은 이 도구에 하드코딩되어 있어 실제보다 오래됐을 수 있으니, 정확한 최신 버전은 직접 확인하세요.)

**권장 수정:**

```
electron 의존성을 최신 안정 메이저로 올리고, 릴리스 노트의 호환성 변경사항을 확인하세요.

// package.json
"devDependencies": {
  "electron": "^<latest-major>.0.0"
}
```

