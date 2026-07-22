# electron-audit

로컬 Electron 프로젝트를 정적 분석해 알려진 Electron 보안 안티패턴(안전하지
않은 `webPreferences`, CSP 미흡, 명령 주입, 위험한 IPC 노출, 검증 없는 외부
URL/원격 데이터 처리 등)을 탐지하고, 심각도별 리포트(터미널/JSON/Markdown)를
출력하는 CLI 도구다. 규칙마다 "왜 위험한지 + 수정 예시 코드"를 함께 제공하는
교육적 리포트가 핵심 가치다.

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
    types.ts         Finding, Rule, Severity 등 핵심 타입
    fileRoleClassifier.ts   파일이 main/preload/renderer 중 무엇인지 분류
    rules/           규칙 하나당 파일 하나 (EA001.ts ...)
    ast/             AST 기반 공용 프리미티브 (webPreferences 추출기 등)
    csp/             CSP 토크나이저 프리미티브
  cli/             ← 얇은 CLI 래퍼
    index.ts         인자 파싱, 엔진 호출
    formatters/      terminal.ts, json.ts, markdown.ts
  config/
    defaultConfig.ts
tests/
  fixtures/          규칙별 취약(vulnerable)/안전(safe) 샘플
  rules/             규칙별 유닛 테스트
```

## 코딩 규약

- TypeScript strict 모드.
- 규칙 하나당 파일 하나(`src/core/rules/EA0xx.ts`).
- 각 규칙은 `{ id, severity, target(탐지대상), whyDangerous(왜위험),
  recommendation(권장수정) }` 구조를 반드시 갖는다.
- 여러 규칙이 같은 판정 로직에서 갈라지는 경우(예: EA020/021/022는 한
  콜사이트를 한 번만 분류해 서로 다른 ruleId를 매기는 동일 분석의 세 등급)
  실제 판정은 `src/core/rules/shared/`에 두고, `rules/EA0xx.ts`는 그 결과를
  자기 ruleId로 필터링해 자신의 whyDangerous/recommendation만 붙이는 얇은
  래퍼로 유지한다. `rules/` 바로 아래 파일은 항상 "파일 하나 = 규칙 ID
  하나"를 지킨다.
- 규칙 리포트에는 **"왜 위험한지 설명 + 수정 예시 코드"**를 반드시 포함한다.
  이게 이 도구의 진짜 가치(교육적 리포트)다.

## 엔진 계약 (core 핵심 타입)

규칙 로직보다 먼저 굳히는 계약. `src/core/types.ts` 등에 반영되어 있다.

- **`Finding`**: `severity`(critical/high/medium/low/info)와 별개로
  `confidence: 'high' | 'heuristic'` 필드를 갖는다. 데이터플로우 기반 규칙
  (EA022/030/050 등)은 오탐이 필연이므로, 리포트에서 확실한 탐지와 휴리스틱
  탐지를 반드시 구분해서 보여준다. 필드명은 `ruleId, severity, confidence,
  file, line, target, whyDangerous, recommendation` 등 전부 영문 — 설명
  "값"은 한국어로 채워도 되지만 필드명은 영문 고정.
- **`Rule`은 두 종류**이며 판별 필드 `kind`로 구분한다:
  - `NodeRule`(`kind: 'node'`) — 파일/AST 노드 단위 매칭 규칙.
  - `AggregateRule`(`kind: 'aggregate'`) — 프로젝트 전체를 다 본 뒤 "어디에도
    없음"을 판정(EA041 등)하거나 창들을 서로 비교(EA006)하는 규칙. 매칭
    파이프라인만으론 표현할 수 없어서 별도 종류로 둔다.
  - `RuleEngine`은 파일을 한 번만 파싱해 그 AST를 NodeRule에 넘기고, 같은
    파싱 결과를 `parsedFiles`로 묶어 AggregateRule에 넘긴다(집계 규칙이 다시
    파싱하지 않도록). 두 종류를 모두 실행하고 결과를 합쳐 `Finding[]`을 낸다.
  - 두 컨텍스트 모두 `project: ProjectContext`를 받는다. 스캐너가
    `package.json`에서 한 번 읽어 채우며, 지금은 `electronMajorVersion`을
    담는다 — EA002/003이 "키 부재"의 위험도를 버전 기본값(contextIsolation
    12+, sandbox 20+)에 따라 판정하는 데 쓴다. 규칙에 프로젝트 전역 사실이
    필요하면 파일마다 다시 읽지 말고 여기에 추가한다.
- **파일 역할 분류**(`main`/`preload`/`renderer`)는 규칙과 분리된 독립 모듈
  `fileRoleClassifier`가 담당한다. `package.json`의 `main` 필드 →
  `webPreferences.preload` 경로 → 파일명 휴리스틱 순으로 판정하고, 불확실하면
  전역 처리 + `confidence` 하향. 오분류가 실질 오탐/미탐의 주원인이므로 단독
  테스트 가능하게 유지한다.
- **공용 프리미티브 3개**를 규칙보다 먼저 만든다. 여러 규칙이 같은 로직을
  중복 구현하지 않게 하기 위함이다.
  1. **webPreferences 추출기**(`src/core/ast/webPreferencesExtractor.ts`) —
     `BrowserWindow` 생성 콜사이트 AST를 정규화된 모델로 변환. A그룹
     (EA001~006) 6개 규칙이 모두 이 결과를 읽는다.
  2. **`isStaticSafeLiteral(node, path)`**(`src/core/ast/isStaticSafeLiteral.ts`,
     `path`는 `@babel/traverse`의 `NodePath` — 단순 파일 경로 문자열로는 scope
     조회가 불가능해서 필요) — 리터럴/같은 파일 `const` 폴딩(체인 포함)/그런
     값들로만 구성된 TemplateLiteral·BinaryExpression(`+`)까지 안전으로 판정.
     const 폴딩 자체는 `src/core/ast/constFolding.ts`의
     `resolveConstIdentifier`를 webPreferences 추출기와 공유(중복 구현 금지).
     EA020/021/022가 사용 중이며 EA040/042도 그대로 재사용 예정.
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

## 규칙 ID 체계

`EA0xx` 넘버링, 그룹별 범위:

| 그룹 | 범위 | 내용 |
| :-- | :-- | :-- |
| A | 001~007 | BrowserWindow / webPreferences |
| B | 010~013 | Content Security Policy |
| C | 020~022 | 명령 실행(command injection) |
| D | 030~032 | IPC |
| E | 040~043 | 외부 상호작용(shell.openExternal, 원격 URL 등) |
| F | 050~051 | 원격 데이터 & 업데이트 |
| G | 060~062 | 기타 위생(텔레메트리, 코드서명, 구버전) |

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
  실제 dnsChanger 소스가 없을 때 spec 4번 패턴을 하나씩 재현한 합성 프로젝트 —
  아직 구현 안 된 규칙(EA006/011/012/040/050 등)에 대응하는 패턴도 미리
  심어 뒀으니, 해당 규칙이 M2에서 추가되면 코드 수정 없이 findings가 자동으로
  늘어난다. 스냅샷은 최초 생성 시 사람이 내용을 승인하는 게 전제 — 규칙을
  바꿔 스냅샷이 깨지면 그게 의도된 변경인지 회귀인지 먼저 판단하고 나서
  `-u`로 갱신한다.
- **FP 코퍼스** (`tests/corpus/clean/`) — 실제로 안전한(자기가 안 쓴)
  Electron 앱에 대해 **"high-confidence이면서 severity critical/high"인 finding=0**
  을 요구(= 기본 종료코드가 실패하는 바로 그 기준, `cli/exitCode.ts`와 일치).
  heuristic이나 high-confidence여도 medium/low/info는 허용 — 안전한 앱도 경미한
  진짜 탐지(예: minimal-repro(구 electron-quick-start)의 style-src `unsafe-inline` → EA011 medium)를
  가질 수 있고, 그게 빌드를 막으면 안 되기 때문. M3 "오탐 없이" 기준을 재는 유일한
  수단. 외부 코드 반입이 필요하므로 도입 전 반드시 사용자 확인을 받는다.

## 명령어 모음

```
npm run build   # tsc -p tsconfig.json
npm test        # vitest run
npm run lint    # eslint .
npm run dev -- <target-path>   # tsx로 로컬 CLI 실행
```

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
  스킵"으로 귀결되고, `RuleEngine`이 카운트만 남긴다.
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
