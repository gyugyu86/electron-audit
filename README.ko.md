# electron-audit

[English README](README.md)

**Electron 앱의 보안 안티패턴을 정적 분석하는 CLI.** 저오탐(low false positives),
데이터플로우 인식, 최신 Electron 지원.

[![npm](https://img.shields.io/npm/v/electron-audit.svg)](https://www.npmjs.com/package/electron-audit)
[![license](https://img.shields.io/npm/l/electron-audit.svg)](https://github.com/gyugyu86/electron-audit/blob/main/LICENSE)
[![CI](https://github.com/gyugyu86/electron-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/gyugyu86/electron-audit/actions/workflows/ci.yml)

로컬 Electron 프로젝트를 지정하면 메인 프로세스·preload·렌더러·설정 파일을 읽어
Electron 앱이 반복적으로 저지르는 보안 실수(렌더러에 Node 권한 노출, 취약한 CSP,
명령 주입, 검증 없는 외부 URL·원격 데이터 처리 등)를 찾아 심각도별로 리포트합니다.
앱을 실행하지 않고 소스만 분석하므로 빠르고 안전하며 CI에 붙이기 좋습니다.

---

## 왜 이 도구인가

Electron 보안 정적 분석은 새로운 분야가 아닙니다.
[Electronegativity](https://github.com/doyensec/electronegativity)가 이 영역을
열었고 여전히 참고할 만한 도구입니다. 다만 무료 오픈소스 버전은 **최신 릴리스가
v1.10.3(2023-03)로 이후 유지보수가 멈췄고, 최신 Electron 버전을 인식하지
못합니다**(실행 시 `Unknown Electron release` 경고). Electron 공식 문서는 아직 이
도구를 가리키고 있습니다. electron-audit은 이걸 **대체하려는 게 아니라 잇습니다** —
커버리지 폭은 Electronegativity가 더 넓지만(HTML/DOM까지 봄), electron-audit의
초점은 폭이 아니라 다음 셋입니다.

- **① 저오탐.** 모든 탐지에 심각도와 **별개의 `confidence`**(high / heuristic)를
  붙여 "확실한 것"과 "의심스러운 것"을 명확히 가릅니다. 그리고 실제로 안전하게 짠
  공개 앱 코퍼스에 대해 **high-confidence 오탐 0**을 **회귀 테스트로 강제**합니다.
- **② 데이터플로우 근사.** 단순 패턴 매칭을 넘어, 신뢰할 수 없는 입력(역직렬화·외부
  응답·IPC 인자)이 위험한 싱크(명령 실행·파일 경로·외부 URL)로 흐르는지 추적합니다
  (선행 무료 도구에 없는 소스→싱크 개념).
- **③ 최신 Electron 지원 + CI 친화.** 최신 버전을 인식하고, SARIF 출력과 저오탐
  기반 종료코드로 GitHub 코드 스캐닝·CI에 자연스럽게 붙습니다.

## 실측 검증

주장 대신 실제 공개 앱으로 검증했고, **우리가 놓친 것까지 정직하게** 기록했습니다.
(범위는 "우리가 실측한 앱들에서"이지, "모든 앱에서 완벽"이 아닙니다.)

- **[dnsChanger-desktop](https://github.com/DnsChanger/dnsChanger-desktop)**(실제 앱)에서
  권한상승 명령 주입 RCE(`sudo.exec`에 스토어 설정값 보간)를 high-confidence로
  탐지 — 선행 도구가 놓치는 지점입니다. 취약한 HTML `<meta>` CSP도 잡습니다.
  → [validation-dnschanger.md](https://github.com/gyugyu86/electron-audit/blob/main/examples/validation-dnschanger.md)
- **성격이 다른 4개 앱**(dnsChanger / zonote / Notable / minimal-repro(구 electron-quick-start))에서
  **high-confidence 오탐 0**, 대형 앱도 무크래시 완주 — FP=0이 특정 앱 현상이
  아니라 일반적으로 성립함을 확인.
  → [validation-overfitting.md](https://github.com/gyugyu86/electron-audit/blob/main/examples/validation-overfitting.md)

## 설치 & 빠른 시작

```bash
# 설치 없이
npx electron-audit <electron-프로젝트-경로>

# 또는 전역 설치
npm install -g electron-audit
electron-audit <electron-프로젝트-경로>
```

터미널 출력 예시(취약 예제 프로젝트):

```
main.js:16
   CRITICAL  EA001  new BrowserWindow({ webPreferences: { nodeIntegration: true } })
     왜 위험한가: nodeIntegration: true는 렌더러에 Node.js API를 그대로 노출합니다 ...
     권장 수정:
       nodeIntegration: false + preload/contextBridge ...
   CRITICAL  EA002  contextIsolation: false
   HIGH      EA006  이 창은 위험하게 설정됐으나 같은 프로젝트의 다른 창은 안전함
updater.js:16
   CRITICAL  EA020  exec(`./run-installer.sh ${info.installerPath}`)
   MEDIUM  [heuristic] EA050  역직렬화된 신뢰 불가 데이터가 검증 없이 셸 명령으로 흘러감
...
총 12건 발견 (critical 5 · high 3 · medium 3 · info 1)
```

전체 예시 리포트:
[Markdown](https://github.com/gyugyu86/electron-audit/blob/main/examples/synthetic-vuln-report.md) ·
[JSON](https://github.com/gyugyu86/electron-audit/blob/main/examples/synthetic-vuln-report.json) ·
[SARIF](https://github.com/gyugyu86/electron-audit/blob/main/examples/dnschanger.sarif)

## 사용법

```bash
electron-audit <경로>              # 터미널 리포트 (기본)
electron-audit <경로> --json       # 구조화 JSON (후속 도구용)
electron-audit <경로> --markdown   # 사람이 읽는 Markdown 리포트
electron-audit <경로> --sarif      # SARIF 2.1.0 (GitHub 코드 스캐닝)
electron-audit <경로> --config <설정파일>   # 규칙 on/off·심각도 오버라이드
```

### confidence: 확실 vs 휴리스틱

모든 탐지에는 심각도와 **별개로** confidence가 붙습니다. `[heuristic]` 태그가
없으면 정적으로 명백한 high-confidence 탐지이고, 있으면 데이터플로우 근사·버전
의존 판정 등 오탐 가능성이 있는 탐지입니다. 이 구분이 이 도구의 신뢰성 기준입니다.

### 설정 파일 (`--config`)

특정 규칙을 끄거나 심각도를 바꿉니다(JSON 또는 `export default` JS). 잘못된 설정은
크래시 대신 친절한 오류를 내고 종료합니다.

```json
{ "ruleOverrides": { "EA062": { "enabled": false }, "EA042": { "severity": "low" } } }
```

### 종료 코드 (CI 게이트)

저오탐 철학을 종료 코드까지 관철합니다 — **오탐으로 빌드를 깨는 도구는 아무도 CI에
두지 않기 때문**입니다.

| 모드 | 종료 코드 1(실패) 조건 |
| :-- | :-- |
| 기본 | **high-confidence이면서 severity critical/high**인 탐지가 하나라도 있을 때 |
| `--strict` | 위 + heuristic이라도 severity critical/high면 실패 |
| `--no-fail` | 항상 0 (리포트 전용) |

heuristic·info·low·medium 탐지로는 기본값이 빌드를 막지 않습니다.

## GitHub Action (코드 스캐닝 연동)

`--sarif` 결과를 GitHub 코드 스캐닝에 올리면 findings가 **Security 탭 + PR 주석**으로
자동 표시됩니다.

```yaml
# .github/workflows/electron-audit.yml
name: electron-audit
on:
  push:
  pull_request:
permissions:
  contents: read
  security-events: write   # SARIF 업로드에 필수
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gyugyu86/electron-audit@v0.1.3
        with:
          path: .                  # 스캔할 프로젝트 경로
          version: 0.1.3           # 스캐너 버전 고정 (기본: latest)
          # fail-on-findings: true # high-confidence critical/high면 체크 실패 (기본)
          # upload: true           # 코드 스캐닝 업로드 (기본)
```

`@v0.1.3` 태그 고정을 권장합니다. supply-chain 관점에서 가장 강한 보장을 원하면
태그가 가리키는 커밋 SHA로 고정하세요 — 저자는 태그는 옮길 수 있어도 커밋 SHA는
옮길 수 없습니다. `git rev-parse v0.1.3^{commit}`로 조회해
`uses: gyugyu86/electron-audit@<sha>  # v0.1.3` 형태로 씁니다.

**스캐너 버전도 고정하세요.** `version:` 입력의 기본값은 `latest`라, 액션만
고정(태그·SHA)해도 스캐너는 **고정되지 않습니다** — 실행 시점의 npm `latest`로
떠버려, 워크플로가 그대로여도 스캔 결과가 달라질 수 있습니다. 위 예시처럼
`version:`을 명시해 액션과 스캐너를 함께 고정해야 스캔이 재현 가능합니다.

findings가 있어도 SARIF는 항상 업로드되며(게이트는 별도 스텝), `fail-on-findings:
false`로 "리포트만"도 가능합니다. GitHub 러너에는 Node가 기본 설치돼 있습니다.

fork에서 올라온 PR에서는 GitHub이 `security-events: write`를 부여하지 않아 업로드
스텝이 건너뛰어집니다 — 오류가 아니라 GitHub 제약입니다. 같은 저장소 브랜치의
실행은 정상 업로드됩니다.

## 규칙 목록 (구현된 21개)

심각도: `critical` > `high` > `medium` > `low` > `info`.

| ID | 그룹 | 심각도 | 탐지 대상 |
| :-- | :-- | :-- | :-- |
| EA001 | A. webPreferences | critical | `nodeIntegration: true` — 렌더러에 Node API 노출 |
| EA002 | A | critical | `contextIsolation: false`(또는 구버전 기본값) |
| EA003 | A | high | `sandbox` 미설정/`false` |
| EA004 | A | high | `webSecurity: false` |
| EA005 | A | medium | `allowRunningInsecureContent: true` |
| EA006 | A | high | 여러 창의 `webPreferences` 불일치(안전한 창 옆의 위험한 창) |
| EA007 | A | high/info | `enableRemoteModule: true`(Electron 14+에선 제거돼 info) |
| EA010 | B. CSP | high | CSP 부재(JS·HTML `<meta>` 어디에도 없음, heuristic) |
| EA011 | B | high/medium | CSP `unsafe-inline`/`unsafe-eval`(script-src·eval=high) |
| EA012 | B | medium | CSP 소스에 와일드카드 `*`(부분 와일드카드 제외) |
| EA013 | B | info | Cordova 잔재(`gap:`) 등 붙여넣기 CSP 시그니처 |
| EA020 | C. 명령 실행 | critical | `exec`/`spawn(shell:true)`에 보간된 명령 문자열 |
| EA021 | C | critical | 위가 `sudo-prompt`류 권한상승과 결합 |
| EA022 | C | high | 셸에 흘러가는 검증 안 된 변수(heuristic) |
| EA040 | E. 외부 상호작용 | high | `shell.openExternal(변수)` — 스킴 화이트리스트 없음 |
| EA041 | E | medium | `setWindowOpenHandler` 부재 또는 무조건 `allow` |
| EA042 | E | medium | `loadURL`에 원격/비-https 리터럴 URL |
| EA050 | F. 원격 데이터 | medium | 신뢰 불가 역직렬화/외부 입력이 검증 없이 위험 싱크로 직행(heuristic) |
| EA060 | G. 위생 | info | 애널리틱스/텔레메트리 SDK(프라이버시 고지) |
| EA061 | G | low | electron-builder 코드 서명 설정 부재 |
| EA062 | G | info | Electron 버전이 최신 대비 크게 뒤처짐 |

## 정직한 한계

정적 분석기이자 JS/TS만 파싱하므로 **일부러 안 잡는** 영역이 있습니다 — 미탐을
허용하더라도 오탐을 피하는 쪽을 택했습니다. 이건 약점이 아니라 신뢰의 조건입니다.

- **HTML은 `<meta>` CSP만 얕게 봅니다.** `<meta http-equiv="Content-Security-Policy">`의
  CSP 값을 정규식으로 추출해 EA010/011/012를 태우지만, 완전한 HTML/DOM 파싱은
  아닙니다 — `<webview>` 속성, `will-navigate` 등은 미지원(v2).
- **데이터플로우는 같은 함수 스코프 내 근사입니다.** EA050은 소스→싱크가 같은 함수
  안에 직결될 때만 잡습니다. 함수 경계를 넘는 흐름, 반환값·재할당 추적은 하지 않습니다.
- **알려진 미탐**(과적합 점검에서 스스로 발견): `data:` URL `loadURL`에 변수 HTML을
  넣는 XSS 벡터, 동적으로 병합/스프레드된 `webPreferences`는 heuristic으로 과소보고.
- **버전 기준은 하드코딩**(EA062): 오프라인·CI 재현성을 위해 "최신 Electron" 기준값이
  코드에 박혀 있어 시간이 지나면 낡습니다(그래서 heuristic). 갱신은 소스 상수 한 줄.
- **런타임 동작은 못 봅니다**: 정적 분석의 일반 한계.

보류 규칙: **EA043**(will-navigate/webview — 완전 HTML 파싱 필요),
**EA051**(electron-updater 서명 검증 — 실제 알려진 RCE 클래스지만 저오탐 정적 판정이
어려움). 노이즈로 내보내지 않고 v2로 보류했습니다.

## 로드맵 (v1.1+)

과적합 점검에서 나온 실제 재료들입니다.

- 동적 `webPreferences` 병합/스프레드 정밀화(현재 heuristic 과소보고).
- `data:` URL `loadURL`(변수 HTML) 미탐 커버.
- `openExternal` 주변 스킴 가드 인식으로 heuristic 노이즈 감소.
- EA043(webview) — 완전한 HTML 파싱과 함께.
- EA051(electron-updater 서명 검증) — 저오탐 시그널 확보 후.

1.0은 초기 사용자 피드백으로 인터페이스를 안정화하는 데 집중합니다.

## 개발 / 기여

```bash
npm install
npm run build   # tsc
npm test        # vitest (규칙 유닛 + 코퍼스 회귀 + 강건성 + FP=0)
npm run lint    # eslint
npm run dev -- <경로>   # 로컬 실행
```

아키텍처·규칙 작성 규약은 [docs/ARCHITECTURE.md](https://github.com/gyugyu86/electron-audit/blob/main/docs/ARCHITECTURE.md)를
참고하세요. 핵심 원칙: 분석 엔진(`src/core`)은 CLI를 모르고, 규칙은 하나당 파일
하나이며, 새 규칙은 취약/안전 fixture와 유닛 테스트를 반드시 함께 추가합니다.

## 이 도구 자체의 보안

이 도구는 **대상 코드를 절대 실행하지 않고**(정적 분석만) 파싱만 합니다. 프로세스를
띄울 때도 셸 보간 없이 `execFile` + 인자 배열만 씁니다. 신뢰할 수 없는 입력(남의
프로젝트 코드)에 대한 강건성(거대·깨진·악의적 파일, 심볼릭 링크 이탈)을 테스트로
고정합니다.

## 라이선스

[MIT](https://github.com/gyugyu86/electron-audit/blob/main/LICENSE)
