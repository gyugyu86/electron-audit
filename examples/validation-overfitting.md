# 과적합 점검: dnsChanger 밖 2개 앱 실측

dnsChanger 하나에 규칙이 과적합됐는지 확인하려고, 성격이 다른 실제 앱 2개에
electron-audit를 돌렸습니다. 핵심 질문: **high-confidence 오탐 0이 dnsChanger에서만
참인가, 일반적으로 참인가?** (과장 없이, 미탐·약점도 그대로 기록.)

| 앱 | 성격 | 라이선스 | 스캔 파일 | 파싱실패 | 크래시 |
| :-- | :-- | :-- | :-: | :-: | :-: |
| [zonote](https://github.com/zonetti/zonote) v0.4.4 | 작은 노트 앱 (CVE-2020-35717) | MIT | 8 | 0 | 없음 |
| [notable](https://github.com/notable/notable/tree/v1.3.0) v1.3.0 | 큰 노트 앱 (23k★) | MIT | 116 | 0 | 없음 |

_두 앱 소스는 /tmp 작업공간에만 두고 분석만 했습니다 — 이 저장소·배포 패키지에
포함하지 않습니다._

---

## zonote (작은 취약 앱 — 미탐 점검)

7건. **high-confidence critical/high 2건, 둘 다 진짜(오탐 0):**

- **EA001 [critical/high]** `src/main/main.js:38` — nodeIntegration:true. ★
  콜사이트는 `new BrowserWindow(browserWindowOptions)`로 **변수**이고, 그 변수는
  같은 파일 const에 `webPreferences: { nodeIntegration: true, enableRemoteModule: true }`.
  const 폴딩으로 정확히 잡음. → **알려진 취약점(CVE-2020-35717)을 dnsChanger가
  아닌 앱에서, 인라인이 아닌 변수 형태로 잡았다** = 과적합의 반대 증거.
- **EA011 [high/high]** `static/index.html:6` — `script-src 'unsafe-inline'`.
  실재. script-src라 등급상 high(정확).

나머지 5건 heuristic/info: EA002/003(키 부재), EA041(핸들러 부재), EA040(노트 링크
href를 openExternal — 노트 내용이 공격자 제어면 위험, heuristic 정당), EA062(electron 9).

관찰: zonote는 CVE가 0.4.1에서 "수정"됐다지만 **master(0.4.4)에도 nodeIntegration:true가
그대로** 남아 있고 CSP도 `script-src 'unsafe-inline'`이라 XSS 방어가 사실상 무력.
우리 도구가 둘 다 정확히 지적.

## notable (큰 실전 앱 — 강건성 + FP 점검)

**116파일 완주, 파싱실패 0, 크래시 0** — 대형 코드베이스에서 강건성 유지. 19건.

**high-confidence critical/high 1건, 진짜(오탐 0):**

- **EA004 [high/high]** `src/main/windows/main.ts:549` — `webSecurity: false`. 실재
  (PDF 출력용 창이 `data:text/html,${options.html}`를 로드하면서 webSecurity를 끔).
  동일출처 정책을 끄는 확실한 오설정. → dnsChanger엔 없던 규칙(EA004)이 여기서
  발화 = 규칙셋이 dnsChanger 소견에만 맞춰지지 않았다는 증거.

나머지 18건 heuristic/info/low: `window.ts:163`의 동적 webPreferences(변수 병합)로
EA001~005 5건 heuristic, EA040 openExternal 7건(링크 많은 앱), EA010(CSP 부재
heuristic), EA061/062(info/low). 전부 비-게이팅.

---

## 종합 판정

### ★ 핵심 질문: high-confidence 오탐 = 0이 일반적인가? → **예**

| 앱 | high-conf critical/high | 그중 오탐 |
| :-- | :-: | :-: |
| dnsChanger (앞선 실측) | 4 | **0** |
| zonote | 2 | **0** |
| notable | 1 | **0** |
| electron-quick-start (clean 코퍼스) | 0 | **0** |

**성격이 완전히 다른 4개 앱(DNS 도구·소형 노트앱·대형 노트앱·공식 샘플)에서
high-confidence 오탐 0.** FP=0은 dnsChanger 특수현상이 아니라 일반적으로 성립.

### 과적합 신호: 없음

- **EA001이 3가지 다른 형태로 nodeIntegration:true를 잡음**: dnsChanger(인라인
  리터럴), zonote(같은 파일 const 변수 → 폴딩), notable(동적 병합 → heuristic).
  코드 스타일에 관계없이 일반화 = dnsChanger 패턴에 맞춘 게 아님.
- **dnsChanger엔 없던 EA004(webSecurity:false)가 notable에서 발화** = 규칙셋이
  한 앱 소견에 편향되지 않음.
- 강건성: 세 앱(98+8+116파일) 전부 무크래시 완주.

### 미탐/약점 → v1.1 로드맵 재료 (지금 고칠 게 아니라 목록)

1. ~~**`enableRemoteModule: true` 무규칙** (zonote)~~ → **1.0에서 처리됨.** EA007
   추가(A그룹 확장): explicit-true는 Electron <14에서 high, 14+에서는 제거된
   설정이라 info로 강등. zonote의 const 변수 형태 `enableRemoteModule: true`를
   재실측으로 잡음(high/high-confidence).
2. **동적 webPreferences 병합/스프레드** (notable `window.ts:163`) — `{...literal},
   options` 병합이나 스프레드면 nodeIntegration:true가 리터럴로 있어도 heuristic으로
   내려감(과소보고, 보수적). 부분 스프레드 해석으로 정밀도 개선 여지.
3. **openExternal heuristic 노이즈** (notable 7건) — 링크 많은 앱은 openExternal이
   흔함. 주변 스킴 가드(예: `startsWith('https:')`)를 인식해 heuristic을 줄이는
   정밀도 개선 여지(현재는 인자가 변수면 무조건 heuristic).
4. **data: URL loadURL** (notable `main.ts:557` `loadURL('data:text/html,${options.html}')`)
   — 변수 HTML을 data: URL로 로드하는 XSS 벡터. EA042는 http/원격 리터럴만 봐서
   놓침(옵션이 크로스함수라 EA050도 안 걸림). v1.1 후보.

### 결론

- ✅ **배포 게이트**: high-confidence 오탐 0이 4개 앱에서 일반적으로 성립.
- ✅ **과적합 아님**: 규칙이 코드 스타일·앱 종류를 넘어 일반화.
- ✅ **강건성**: 대형 앱 포함 무크래시.
- 📌 **v1.1 재료**: enableRemoteModule, 동적 webPreferences 병합, openExternal
  가드 인식, data: URL loadURL — 미탐/정밀도 항목(고침 아님, 목록화).
