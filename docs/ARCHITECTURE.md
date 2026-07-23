# electron-audit

로컬 Electron 프로젝트를 정적 분석해 알려진 Electron 보안 안티패턴(안전하지
않은 `webPreferences`, CSP 미흡, 명령 주입, 검증 없는 외부 URL/원격 데이터
처리 등)을 탐지하고, 심각도별 리포트(터미널/JSON/Markdown/SARIF)를 출력하는
CLI 도구다. GitHub code scanning 연동용 composite action(`action.yml`,
`npx electron-audit --sarif`를 실행)도 제공한다. 규칙마다 "왜 위험한지 +
수정 예시 코드"를 함께 제공하는 교육적 리포트가 핵심 가치다.

## 아키텍처 원칙

- **`core`(분석 엔진)는 CLI를 모른다.** `core`는 파일 스캔·AST 분석·규칙
  실행·`Finding[]` 생성까지만 책임진다. 출력 포맷·인자 파싱은 `cli`에만 존재.
- 이 분리 덕분에 나중에 GUI나 GitHub Action을 얹을 때 `core`를 그대로
  재사용한다. `core` → `cli`/`gui`/`action` 방향의 단방향 의존성만 허용.

## 폴더 구조

```
src/
  core/            ← 재사용 가능한 분석 엔진 (UI 무관)
    scanner.ts       파일 수집·필터
    ruleEngine.ts    규칙 실행·수집
    report.ts        결과 구조체(Finding[]) → 포맷 무관
    types.ts         Finding, Rule, Severity, ProjectContext 등 핵심 타입
    index.ts         core 공개 API 배럴 (GUI/Action이 직접 import하는 표면)
    parser.ts        @babel/parser 래퍼 — 모든 파싱 실패를 undefined로 흡수
    config.ts        --config 로더(규칙 on/off·심각도 오버라이드)
    electronVersion.ts   package.json에서 electron major 버전 판독
    projectMetadata.ts   rootDir/packageJsonPath/dependencyNames/build 수집
    url.ts           URL 스킴 파싱 헬퍼
    fileRoleClassifier.ts   파일이 main/preload/renderer 중 무엇인지 분류
    rules/           규칙 하나당 파일 하나 (EA001.ts ...)
      index.ts         ALL_RULES — 구현된 전체 규칙 목록(단일 진실원)
      shared/          여러 규칙이 공유하는 "분류" 로직(아래 규약 참조)
    ast/             규칙이 조회하는 AST 공용 프리미티브(아래 프리미티브 참조)
    csp/             cspTokenizer.ts + htmlCspExtractor.ts(HTML <meta> CSP)
  cli/             ← 얇은 CLI 래퍼
    index.ts         인자 파싱, 엔진 호출, 종료코드 결정
    exitCode.ts      종료코드 정책(default/strict/none)
    messages.ts      사용자 노출 문자열 상수(영문; 향후 로케일 추가 대비 flat)
    formatters/      terminal.ts, json.ts, markdown.ts, sarif.ts, reportModel.ts
  config/
    defaultConfig.ts
scripts/           ← 빌드/테스트 보조(엔진 아님)
  fetchCleanCorpus.ts    Tier-1 clean 코퍼스 SHA 핀 clone
  checkCleanCorpus.ts    clean 코퍼스 FP 게이트 스캔
tests/
  fixtures/          규칙별 취약(vulnerable)/안전(safe) 샘플
  rules/             규칙별 유닛 테스트
  cli/               포맷터/exitCode 등 CLI 계층 테스트
  core/              config/파서 등 core 헬퍼 테스트
  corpus/            코퍼스 회귀 스냅샷 + FP(clean) 코퍼스
.github/workflows/   ci.yml, self-scan.yml, clean-corpus.yml
```

## 코딩 규약

- TypeScript strict 모드.
- 규칙 하나당 파일 하나(`src/core/rules/EA0xx.ts`).
- 각 규칙은 `{ id, severity, target(탐지대상), whyDangerous(왜위험),
  recommendation(권장수정) }` 구조를 반드시 갖는다.
- 공유 로직은 성격에 따라 **두 위치**로 나뉜다. 혼동하면 안 된다:
  - **`src/core/rules/shared/`** — "한 콜사이트를 **한 번 분류**해 여러 ruleId로
    갈라지는(팬아웃)" 판정. 예: EA020/021/022는 한 명령 실행 콜사이트를 한 번만
    분류(`commandInjection.ts`)해 인자 위험도·싱크 종류에 따라 셋 중 하나의
    ruleId를 매긴다. `rules/EA0xx.ts`는 그 결과를 자기 ruleId로 필터링해 자신의
    whyDangerous/recommendation만 붙이는 얇은 래퍼로 유지한다.
  - **`src/core/ast/`** — "여러 규칙이 **각자 조회**하는 공용 프리미티브"(팬아웃
    아님, 단순 헬퍼). 예: `isStaticSafeLiteral`, `schemeGuard`. 한 규칙만 지금
    쓰더라도 성격상 여러 규칙이 참조할 헬퍼면 여기에 둔다(그래서 EA040 전용인
    `schemeGuard`도 `rules/shared/`가 아니라 `core/ast/`에 있다 — EA042/EA050이
    같은 스킴-가드 판정을 재사용할 여지가 있는 프리미티브이기 때문).
  - `rules/` 바로 아래 파일은 항상 "파일 하나 = 규칙 ID 하나"를 지킨다.
- 규칙 리포트에는 **"왜 위험한지 설명 + 수정 예시 코드"**를 반드시 포함한다.
  이게 이 도구의 진짜 가치(교육적 리포트)다.

## 엔진 계약 (core 핵심 타입)

규칙 로직보다 먼저 굳히는 계약. `src/core/types.ts` 등에 반영되어 있다.

- **`Finding`**: `severity`(critical/high/medium/low/info)와 별개로
  `confidence: 'high' | 'heuristic'` 필드를 갖는다. 데이터플로우 기반 규칙
  (EA022/050 등)은 오탐이 필연이므로, 리포트에서 확실한 탐지와 휴리스틱
  탐지를 반드시 구분해서 보여준다. 필드명(`ruleId, severity, confidence,
  file, line, target, whyDangerous, recommendation` 등)은 물론, 사용자에게
  노출되는 문자열 "값"(whyDangerous/recommendation, CLI usage/help,
  포맷터 라벨, config 오류 메시지)도 **전부 영문**이다 — 공개 repo·npm 패키지라
  영문으로 통일했다. CLI 계층의 노출 문자열은 `src/cli/messages.ts` 한 곳에
  상수로 모아 두었고(향후 로케일 추가 대비 flat 키 구조), core는
  자기 문자열을 자기 안에 둔다(core→cli 단방향 의존 유지).
- **`Rule`은 두 종류**이며 판별 필드 `kind`로 구분한다:
  - `NodeRule`(`kind: 'node'`) — 파일/AST 노드 단위 매칭 규칙.
  - `AggregateRule`(`kind: 'aggregate'`) — 프로젝트 전체를 다 본 뒤 "어디에도
    없음"을 판정(EA041 등)하거나 창들을 서로 비교(EA006)하는 규칙. 매칭
    파이프라인만으론 표현할 수 없어서 별도 종류로 둔다.
  - `RuleEngine`은 파일을 한 번만 파싱해 그 AST를 NodeRule에 넘기고, 같은
    파싱 결과를 `parsedFiles`로 묶어 AggregateRule에 넘긴다(집계 규칙이 다시
    파싱하지 않도록). 두 종류를 모두 실행하고 결과를 합쳐 `Finding[]`을 낸다.
  - 두 컨텍스트 모두 `project: ProjectContext`를 받는다. 스캐너가 스캔 시작 시
    한 번 채우며, 현재 담는 필드는: `electronMajorVersion`(EA002/003이 "키
    부재"의 위험도를 버전 기본값 — contextIsolation 12+, sandbox 20+ — 에 따라
    판정, EA062가 구버전 판정), `rootDir`, `packageJsonPath`(매니페스트 자체를
    앵커로 하는 EA060/061/062용), `dependencyNames`(EA060 텔레메트리 SDK·EA061
    electron-builder 사용 여부), `packageJsonBuild`(EA061 서명 설정 점검),
    `htmlCspSites`(HTML `<meta>` CSP — 아래 CSP 프리미티브 참조). 규칙에
    프로젝트 전역 사실이 필요하면 파일마다 다시 읽지 말고 여기에 추가한다.
- **파일 역할 분류**(`main`/`preload`/`renderer`)는 규칙과 분리된 독립 모듈
  `fileRoleClassifier`가 담당한다. `package.json`의 `main` 필드 →
  `webPreferences.preload` 경로 → 파일명 휴리스틱 순으로 판정하고, 불확실하면
  전역 처리 + `confidence` 하향. 오분류가 실질 오탐/미탐의 주원인이므로 단독
  테스트 가능하게 유지한다.
- **공용 프리미티브 5개**를 규칙보다 먼저(또는 규칙과 함께) 만든다. 여러 규칙이
  같은 로직을 중복 구현하지 않게 하기 위함이다.
  1. **webPreferences 추출기**(`src/core/ast/webPreferencesExtractor.ts`) —
     `BrowserWindow` 생성 콜사이트 AST를 각 필드의 4-state(explicit-true/
     explicit-false/absent/dynamic) 모델로 정규화. A그룹 EA001~007이 이 결과를
     읽고, EA010(CSP 부재 게이트)·EA041(창 안전성 참조)도 `windowCallSites.ts`를
     통해 같은 결과를 재사용한다. 옵션이 `new BrowserWindow(getOptions())`처럼
     같은 파일 헬퍼 함수 호출로 주어지면 아래 5번 프리미티브로 정적 해석한다.
  2. **`isStaticSafeLiteral(node, path)`**(`src/core/ast/isStaticSafeLiteral.ts`,
     `path`는 `@babel/traverse`의 `NodePath` — 단순 파일 경로 문자열로는 scope
     조회가 불가능해서 필요) — 리터럴/같은 파일 `const` 폴딩(체인 포함)/그런
     값들로만 구성된 TemplateLiteral·BinaryExpression(`+`)까지 안전으로 판정.
     const 폴딩 자체는 `src/core/ast/constFolding.ts`의
     `resolveConstIdentifier`를 webPreferences 추출기와 공유(중복 구현 금지).
     EA020/021/022와 EA040이 사용 중이다(EA042는 같은 constFolding 계열
     `resolveStaticString`을 쓴다).
  3. **CSP 토크나이저**(`src/core/csp/cspTokenizer.ts`) — 디렉티브(`;` split)
     → 소스(공백 split) 2단계 토크나이즈. EA011/012가 사용. 와일드카드 판정은
     반드시 토큰 단위로 해야 `*.foo.com` 같은 부분 와일드카드를 `*` 오탐으로
     잡지 않는다. `csp/`에는 이 프리미티브만 두고, CSP **부재** 판정(EA010,
     AggregateRule)이나 Cordova 잔재 시그니처(EA013) 같은 규칙 자체는
     `src/core/rules/`에 둔다. CSP **소스**는 JS 응답헤더 + HTML `<meta>` 양쪽
     — HTML은 `src/core/csp/htmlCspExtractor.ts`가 정규식으로 `<meta>` CSP
     문자열만 얕게 추출(완전 HTML 파싱·parse5는 도입 안 함, v2 사안)해
     `ProjectContext.htmlCspSites`로 넘기고, EA010/011/012가 JS·HTML을 합친
     하나의 CSP 목록(`collectCspStrings`)을 본다. EA011은 디렉티브별로 등급을
     나눈다(script-src/default-src의 unsafe-inline·모든 unsafe-eval=high, 그
     외 unsafe-inline=medium). 그래서 EA011/012는 NodeRule이 아니라
     AggregateRule이다(HTML CSP는 프로젝트 전역 데이터라서).
  4. **`hasDominatingSchemeGuard(callPath, arg)`**(`src/core/ast/schemeGuard.ts`)
     — `shell.openExternal(url)` 같은 호출에 대해, 같은 함수 스코프 안의 스킴
     화이트리스트 가드가 (ㄱ) 그 호출을 **지배(dominate)**하고 (ㄴ) 싱크에
     도달하는 값과 **동일한 바인딩**을 검사하며 (ㄷ) 허용 집합이 http/https의
     부분집합임이 정적으로 증명되는지를 판정한다. `protocol === 'https:'` 등식,
     인라인 배열 `.includes`, `startsWith` 프리픽스, early-return 가드 형태를
     인식한다. 정적으로 증명 못 하는 형태(다른 함수로 분리된 검증, http/https
     외 스킴 혼입, 다른 값 검사, 비지배, 재할당)는 **전부 "가드 없음"으로**
     떨어뜨린다 — 이 판정의 실패 모드는 오탐이 아니라 미탐이므로 안전 측(발화
     유지)으로 실패한다. EA040이 사용하며, 미래 재사용자는 EA042/EA050.
  5. **`resolveLocalFunctionReturnObject(callNode, path)`**
     (`src/core/ast/localFunctionReturn.ts`) — `fn()` 호출을 같은 파일 함수가
     **무조건 반환하는 객체 리터럴**로 정적 해석한다. `new
     BrowserWindow(getOptions())`처럼 옵션을 헬퍼 함수로 빼는 흔한 관용구를
     위해 webPreferences 추출기의 `resolveOptionsObject`에서만 쓴다. 허용
     조건(전부 충족 시에만 해석, 하나라도 어긋나면 `dynamic` 유지):
     bare-identifier callee / 같은 파일 비재할당 함수(선언 또는 const 화살표·
     함수식) / 인자 0개 / 단일 무조건 top-level return / 객체 리터럴 /
     top-level spread 없음. const-함수 케이스는
     `constFolding.resolveConstIdentifier`를 재사용하되 `constFolding.ts`
     자체는 건드리지 않아, 이 프리미티브는 EA020/021/022(명령 주입) 판정과
     격리된다. 증명 안 되면 `dynamic` 유지 = 종전대로 heuristic 발화(미탐 방지).

이 5개와 별개로 **`collectImportBindings(ast)`**(`src/core/rules/shared/importBindings.ts`)
가 모든 규칙의 import/require 인식 지점을 하나로 모은다 — EA020/021/022
(`commandInjection.ts` 경유)·EA040·EA050·EA060이 전부 이걸 쓴다. `core/ast/`가
아니라 `rules/shared/`에 있는 건 성격이 달라서다: 위 5개는 규칙이 **직접
호출하는** AST 판정 프리미티브지만, 이건 파일당 한 번 **수집**만 해서 그 결과
(`ImportBinding.source`/`importedName`)를 규칙에 건네는 쪽이다. 이 수집 지점에
`normalizeModuleSource(source)`가 내장돼 있어, `node:child_process` 같은
Node 빌트인-프로토콜 prefix를 벗겨 `child_process`로 통일한다(서브패스는
보존 — `node:fs/promises` → `fs/promises`, `fs`로 뭉개지 않음). npm 패키지
이름은 `:`를 못 담으므로 이 정규화가 서드파티 임포트를 건드릴 일은 없다.
정규화는 수집 시점 한 곳(`collectEsmImport`/`requireSource`)에만 있고, 소비
규칙은 항상 이미 정규화된 `source`를 읽는다 — 규칙마다 `node:` 유무를
각자 처리하면 그중 하나만 놓쳐도 조용한 미탐이 되므로(과거 실제로
`child_process`만 인식하고 `node:child_process`를 놓쳤던 버그), 여기 한 곳에
모아 둔다.

## 규칙 ID 체계

`EA0xx` 넘버링, 그룹별 범위:

범위는 넘버링 예약을 포함한 계획이고, "구현" 열이 현재 실제 상태다.

| 그룹 | 범위 | 내용 | 구현 |
| :-- | :-- | :-- | :-- |
| A | 001~007 | BrowserWindow / webPreferences | 전부 |
| B | 010~013 | Content Security Policy | 전부 |
| C | 020~022 | 명령 실행(command injection) | 전부 |
| D | 030~032 | IPC | 미구현(넘버링 예약) |
| E | 040~043 | 외부 상호작용(shell.openExternal, 원격 URL 등) | 040·041·042 (043 보류) |
| F | 050~051 | 원격 데이터 & 업데이트 | 050 (051 = v2 후보 #1) |
| G | 060~062 | 기타 위생(텔레메트리, 코드서명, 구버전) | 전부 |

구현된 규칙은 `src/core/rules/index.ts`의 `ALL_RULES`가 단일 진실원이다(현재
21개 항목 — EA041은 absence + unconditional-allow 두 facet이 같은 ruleId
'EA041'을 낸다). 보류(EA043 webview/will-navigate, EA051 자동 업데이트 서명)의
사유는 `ALL_RULES` 주석에 상세히 적혀 있다 — 저오탐 정적 신호를 아직 못 만든
것이 유일한 이유이며, 특히 EA051은 위험이 실제한 v2 최우선 후보다.

심각도 레벨(5단계): `critical` > `high` > `medium` > `low` > `info`.

## 테스트 규약

규칙마다 `tests/fixtures/`에 취약(vulnerable)/안전(safe) fixture 쌍과
`tests/rules/`에 대응하는 유닛 테스트를 함께 만든다. 새 규칙을 추가할 때
fixture·테스트 없이 규칙만 추가하지 않는다.

테스트 하니스는 3개 층으로 나뉜다:
- **적대적 입력 강건성** (`tests/rules/adversarialRobustness.test.ts`,
  `tests/rules/scannerPathSafety.test.ts`) — 거대 파일/깊은 중첩/바이너리를
  `.js` 확장자로 넣은 것/루트 밖을 가리키는 심볼릭 링크가 크래시·행 없이
  스킵되는지 고정. 픽스처는 커밋하지 않고 테스트 실행 시 `os.tmpdir()`에
  생성 후 정리한다(거대/바이너리 파일을 저장소에 넣지 않기 위함).
- **코퍼스 회귀(스냅샷)** (`tests/corpus/`) — `src/core/rules/index.ts`의
  `ALL_RULES`(CLI도 동일하게 사용하는 전체 규칙 목록) 전체를 실제(또는 합성)
  프로젝트에 통째로 돌려 findings를 vitest 스냅샷으로 고정. 규칙 A를 고쳤을 때
  규칙 B의 출력이 의도치 않게 바뀌는 걸 잡는 용도. `tests/corpus/synthetic-vuln/`은
  실제 dnsChanger 소스가 없을 때 spec 4번 패턴을 하나씩 재현한 합성 프로젝트로,
  구현된 규칙 전반(A~C·E~G)에 대응하는 패턴을 심어 두었다. 스냅샷은 최초 생성 시
  사람이 내용을 승인하는 게 전제 — 규칙을 바꿔 스냅샷이 깨지면 그게 의도된
  변경인지 회귀인지 먼저 판단하고 나서 `-u`로 갱신한다(무심코 `-u` 금지).
  스냅샷에는 라벨 문자열이 아니라 ruleId/severity/confidence/file/line만 고정하므로,
  포맷터 라벨이나 문구를 바꿔도 이 스냅샷은 깨지지 않는다.
- **FP(clean) 코퍼스** (`tests/corpus/clean/`) — 실제로 안전한(자기가 안 쓴)
  Electron 앱에 대해 **"high-confidence이면서 severity critical/high"인 finding=0**
  을 요구. 이 기준은 하드코딩하지 않고 `cli/exitCode.ts`의 `computeExitCode(…,
  'default')`를 finding별로 재사용해 판정한다 — 그래서 이 게이트는 도구가
  소비자 CI를 실제로 실패시키는 기준과 정의상 어긋날 수 없다. heuristic이나
  high-confidence여도 medium/low/info는 허용 — 안전한 앱도 경미한 진짜 탐지(예:
  minimal-repro(구 electron-quick-start)의 style-src `unsafe-inline` → EA011
  medium)를 가질 수 있고 그게 빌드를 막으면 안 되기 때문. 두 층으로 구성된다:
  - **벤더 코퍼스**(`tests/corpus/clean/minimal-repro/`) — 소량 파일을 저장소에
    직접 벤더링(출처·SHA는 `PROVENANCE.md`). 오프라인이라 `npm test`에 포함되며
    `cleanCorpus.test.ts`가 검사한다.
  - **Tier-1 체크아웃**(`tests/corpus/clean/tier1.json` → `.checkouts/`) — 실제
    서드파티 레포(`electron/fiddle`, `electron/minimal-repro`)를 **정확한 커밋
    SHA로 핀 고정**해 스크립트로 clone한다. 소스를 벤더링하지 않고(`.checkouts/`는
    gitignore), `npm run corpus:fetch`가 얕게(`--depth 1`) 받고
    `npm run test:corpus:clean`이 스캔한다. 네트워크가 필요하므로 `npm test`에서
    분리해 별도 워크플로(`clean-corpus.yml`)로 돌리고, 체크아웃이 없으면 실패가
    아니라 skip(오프라인 개발자가 막히지 않게)한다. SHA 핀은 upstream이 움직여도
    게이트가 이유 없이 깨지거나 조용히 통과하지 않게 하기 위함이며, SHA를 올릴
    때 `tests/corpus/clean/README.md`의 참고용 분포표도 함께 갱신한다.
  M3 "오탐 없이" 기준을 재는 핵심 수단이다. **외부 코드를 저장소에 반입(벤더링)할
  때는 도입 전 반드시 사용자 확인을 받는다**(Tier-1은 clone 방식이라 반입이 아님;
  Tier-2 이상 신규 대상 추가도 사전 확인 대상).

## 명령어 모음

```
npm run build   # rm -rf dist && tsc -p tsconfig.json && chmod +x dist/cli/index.js
                # (dist/를 먼저 지운다 — tsc는 소스가 옮겨지거나 삭제돼도 옛
                #  출력 파일을 안 지우므로, 청소 없이는 잔재가 tarball에 실린다)
npm test        # vitest run  (오프라인; Tier-1 clean 코퍼스는 제외)
npm run lint    # eslint .
npm run dev -- <target-path>   # tsx로 로컬 CLI 실행 (빌드 없이)

# clean 코퍼스(네트워크 필요, npm test와 분리):
npm run corpus:fetch        # tier1.json의 SHA 핀으로 서드파티 레포 clone
npm run test:corpus:clean   # 핀 고정 체크아웃을 스캔해 FP 게이트 검사
```

## GitHub Action의 스캐너 버전 정책

`action.yml`의 `version` 입력 기본값은 **의도적으로 `latest`**이며, 호출된
ref에서 스캐너 버전을 자동 도출하지 않는다. 재현성이 필요한 사용자에게는
`version:` 명시 지정(그리고 액션 자체는 SHA 핀 고정)을 README에서 요구한다.
자동화를 하지 않기로 한 이유(재론 방지용 기록):

- ref 기반 자동 도출(`github.action_ref`)은 재현성을 가장 원하는 SHA 핀
  사용자에게 무효다 — ref가 커밋 SHA면 스캐너 버전으로 매핑되지 않는다.
- 릴리스마다 기본값을 그 릴리스 버전으로 고정하는 방식은, 기본값을 올린
  커밋과 npm publish 사이에 `@main` 사용자가 존재하지 않는 버전을 받아
  깨지는 구간을 만든다.
- 이 툴 전체가 "정적으로 증명 못 하면 안전 측으로 떨어뜨린다"는 원칙 위에
  서 있다. 액션의 스캐너 버전만 추론으로 채우는 것은 그 태도와 어긋난다 —
  명시를 요구하는 쪽이 일관된다.

## 도구 자체의 보안 원칙

이 도구 스스로도 안전하게 짠다. 대상 프로젝트 코드를 분석할 때 절대 셸
보간(`exec`, 템플릿 문자열로 만든 명령어)을 쓰지 않고, 프로세스를 실행해야
하면 반드시 `execFile` + 인자 배열만 사용한다.

이 도구의 실제 공격 표면은 "신뢰할 수 없는 입력(남의 프로젝트 코드)을 파싱·
처리하는" 지점이다(자기 자신을 스캔하는 건 spec 4번 위협모델과 무관 — CLI는
BrowserWindow도 IPC도 없다). 그래서 강건성 요구는 자기 자신이 아니라 스캔
대상을 향한다:
- `scanner.ts`가 파일 크기 상한(기본 2MB, `ScanOptions.maxFileSizeBytes`로
  조정 가능)을 넘는 파일은 읽지도 않고 스킵한다.
- `scanner.ts`가 스캔 루트를 `realpathSync`로 정규화하고, 그 밖을 가리키는
  심볼릭 링크(파일·디렉토리 모두)는 따라가지 않는다. 루트 내부를 가리키는
  심볼릭 링크가 조상 디렉토리로 되돌아가는 순환도 방문한 real path 집합으로
  막는다.
- `parser.ts`의 `parseSource`는 모든 파싱 실패(문법 오류, 깊은 중첩으로 인한
  스택 오버플로 `RangeError`, 바이너리/깨진 인코딩으로 인한 `SyntaxError`
  등)를 동일하게 `undefined`로 흡수한다 — 크래시 대신 항상 "이 파일은
  스킵"으로 귀결되고, `RuleEngine`이 `filesUnparsable`로 카운트한다.
- **`parseSource`는 문법 실패만 방어한다 — traverse 실패는 별도 계층이 막는다.**
  구문은 유효하지만 babel의 지연(lazy) scope-crawl이 첫 `traverse()` 호출에서
  던지는 경우(예: 같은 스코프 중복 선언 → `TypeError: Duplicate declaration`)가
  있다 — `parse()`는 통과하므로 `parseSource`의 흡수를 거치지 않는다. 그래서
  `RuleEngine.run()`이 파일마다 규칙 실행을 통째로 try/catch로 감싼다: 그 파일의
  findings를 버퍼링하다 던지면 파일 전체를 폐기하고, 결정적으로 `parsedFiles`에도
  넣지 않는다(그래야 `parsedFiles`만 순회하는 AggregateRule 쪽에서 같은 파일을
  다시 만나 재크래시하지 않는다). 파일 단위로 감싸는 이유는 scope-crawl이 첫
  traverse에서만 터지므로 규칙마다 감싸면 규칙 수만큼(현재 21개) 같은 실패를
  반복해서 맞기 때문이다. 이렇게 스킵된 파일은 `filesUnparsable`과 별도인
  `filesAnalysisErrors`로 카운트한다 — 실패 단계가 다르기 때문이며(파싱 vs 분석),
  이 구분이 없으면 "파일이 왜 하나 덜 스캔됐는지"를 사람이 추적할 수 없다. 두
  카운트 모두 조용히 삼키지 않고 터미널/JSON/Markdown 리포트에 노출되고,
  `ELECTRON_AUDIT_DEBUG=1`이면 스킵된 파일별 에러 메시지가 stderr로 나온다.
- `parseSource`의 파서 플러그인은 **확장자로 선택**한다: `.ts`/`.mts`/`.cts`는
  `typescript`만(jsx 끔), 그 외(`.tsx`/`.jsx`/`.js`)는 `typescript`+`jsx`를 함께
  켠다. 이건 휴리스틱이 아니라 TypeScript 언어 사양 그대로다 — `.ts`에서 `<T>`는
  항상 제네릭이고 JSX일 수 없는데(JSX는 `.tsx`에서만 유효), 확장자 무관하게
  jsx를 켜 두면 `.ts` 파일의 제네릭(`function f<T>()`, `const g = <T>(x: T) =>
  x`)의 `<`를 JSX 여는 태그로 오인해 파싱이 실패한다 — 그 파일이 통째로
  스킵되는 **조용한 미탐**이었다(실제 취약점을 담은 `.ts` 파일이 놓쳤을 수
  있었다). `.js`는 React 프로젝트가 JSX를 순수 `.js`에 쓰는 관행이 있어 jsx를
  계속 켜 둔다.
- 대상 코드 처리에 정규식을 쓸 때는 백트래킹 폭발(ReDoS)이 없는 선형 패턴만
  사용한다.

## 모듈 시스템

- 순수 ESM. `package.json`은 `"type": "module"` (`chalk` v5가 순수 ESM이라
  CJS면 깨진다).
- `tsconfig`의 `module`/`moduleResolution`은 모두 `NodeNext`(`ESNext` 아님) —
  tsc 빌드 결과를 번들러 없이 Node가 직접 실행하기 때문. TS 소스의 상대
  import에도 `.js` 확장자를 붙인다(`./foo.js`).
- 런타임 AST 파서(`@babel/parser`)는 **dependency** — `core`가 대상
  프로젝트 코드를 실행 시점에 파싱하므로. `@typescript-eslint/parser`는 이
  프로젝트 자체 린트용 **devDependency**로만 쓰고 대상 코드 파싱에는 쓰지
  않는다.

## 커밋 규칙

마일스톤 또는 규칙 단위로 작게 커밋한다. 규칙 하나를 추가했으면 (규칙 +
fixture + 테스트)를 한 커밋으로 묶는다.
