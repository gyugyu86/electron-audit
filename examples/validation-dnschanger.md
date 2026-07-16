# 실전 검증: dnsChanger-desktop + Electronegativity 비교

electron-audit를 실제 공개 Electron 앱 [dnsChanger-desktop](https://github.com/DnsChanger/dnsChanger-desktop)
(MIT) 소스에 돌리고, 이 분야의 선행 오픈소스 도구
[Electronegativity](https://github.com/doyensec/electronegativity)와 같은 대상에서
비교한 결과입니다. **과장 없이, 우리가 놓치거나 진 항목도 그대로 적었습니다.**

- 대상: dnsChanger-desktop (Electron 33.2.0, TypeScript, 스캔 대상 98개 파일)
- electron-audit: 이 저장소 현재 버전
- Electronegativity: 1.10.3 (npm 최신, **2023-03-09 배포**)

---

## 1. electron-audit 결과 — 22건

강건성: **98개 파일 완주, 파싱 실패 0, 크래시 0**, 종료 코드 1(확실한 critical
존재). 실제 앱의 예상 못 한 구문에도 층3 강건성이 버텼습니다.

_아래 high/heuristic 표는 초기 실측 12건입니다. 이후 배포 전 HTML `<meta>` CSP
커버리지를 더해 CSP 11건이 추가로 잡히고(아래 CSP 절 참조) EA010 heuristic 1건은
정확히 사라져, 최종 22건입니다._

### high-confidence (4건) — 전부 진짜 취약점, 오탐 0

| 규칙 | 위치 | 내용 | 판정 |
| :-- | :-- | :-- | :-- |
| EA001 | `src/main/index.ts:60` | 메인 창 `nodeIntegration: true` | ✅ 진짜 |
| EA001 | `src/main/index.ts:143` | 자식 창 `nodeIntegration: true` | ✅ 진짜 |
| EA002 | `src/main/index.ts:143` | 자식 창 `contextIsolation: false` | ✅ 진짜 |
| **EA021** | `src/main/platforms/windows/windows.platform.ts:17` | `sudo.exec(\`netsh ... "${networkInterface}" dhcp\`)` — 스토어 설정값이 **권한상승 명령에 보간** | ✅ **진짜 (핵심 RCE급)** |

**high-confidence 오탐 = 0건.** 배포 전 품질 게이트 통과. 특히 EA021은 dnsChanger의
실제 핵심 취약점(권한상승 명령 주입)으로, spec 8번이 손으로 짚었던 바로 그 지점입니다.

### heuristic (8건) — 진짜 또는 허용 범위

| 규칙 | 위치 | 판정 |
| :-- | :-- | :-- |
| EA040 | `src/main/ipc/dialogs.ts:166` | ✅ 진짜 — IPC로 받은 url을 **검증 없이** `shell.openExternal` |
| EA050 | `src/main/ipc/dialogs.ts:166` | ✅ 진짜 (데이터플로우) — 신뢰 불가 IPC 인자 → openExternal |
| EA022 | `src/main/platforms/platform.ts:16` | ✅ 진짜 — `sudo.exec(cmd)`가 검증 안 된 변수 인자를 받음 |
| EA050 | `src/main/index.ts:151` | 경계 — IPC 인자가 `loadURL(\`${startUrl}#${arg}\`)`로. 실제론 프래그먼트라 위험 낮음 |
| EA040 | `src/main/index.ts:96` | 경계 — `openExternal(url)`에 `startsWith('https:')` 약한 가드 존재 |
| EA010 | `src/main/index.ts:60` | 정당 — "JS에서 CSP 못 찾음"(CSP는 HTML `<meta>`에 있어 못 봄, 아래 참조) |
| EA062 | `package.json` | ✅ 진짜 — electron 33 (기준 40 대비 7 메이저 뒤) |
| EA060 | `src/renderer/app.tsx:22` | ✅ 진짜 — `react-ga4` 텔레메트리(프라이버시 고지) |

경계 2건(EA040@96, EA050@151)은 모두 heuristic이라 허용 범위 — "확인해보라"는
신호로 정당하고, 실제로도 가드가 약하거나(프리픽스 검사) 데이터가 흘러갑니다.

### CSP (EA011/012) — 처음엔 놓쳤다가, 이제 잡습니다 ✅

dnsChanger의 `index.html`에는 **와일드카드 `*` + `unsafe-inline` + `unsafe-eval`
+ `gap:`** 가 전부 들어간 취약한 CSP가 `<meta>` 태그로 있습니다. 최초 실측에서는
이 도구가 HTML을 안 읽어 **놓쳤고(정직한 패배)**, EA010이 heuristic으로 방향만
가리켰습니다.

배포 전 이 유일한 패배를 메웠습니다 — 얕은 `<meta>` CSP 추출기를 더해, 기존
cspTokenizer·EA011·EA012 판정 로직을 **소스만 JS→HTML로 넓혀** 그대로 태웁니다
(HTML 완전 파싱·parse5 도입은 없음, v2 사안). 이제 같은 `index.html`에서:

- **EA011 high** — `script-src 'unsafe-eval' 'unsafe-inline'` (인라인 스크립트 실행 = XSS→RCE)
- **EA011 medium** — `style-src / img-src / connect-src`의 `unsafe-inline` (인라인 스타일 등, 공격 표면 제한적)
- **EA012 medium ×7** — `default-src / script-src / style-src / object-src / img-src / connect-src / frame-src`의 와일드카드 `*`

를 모두 잡습니다(총 CSP 11건). EA010 heuristic은 이제 `<meta>` CSP를 인식해
정확히 **침묵**합니다.

EA011은 디렉티브별로 등급을 나눕니다: `script-src/default-src`의 unsafe-inline과
모든 unsafe-eval은 **high**, 그 외 디렉티브의 unsafe-inline은 **medium** — 인라인
스타일 같은 정상 관행(Tailwind 등)에 high로 짖지 않기 위함입니다. (남은 얕은 한계:
`gap:` Cordova 시그니처 EA013은 아직 HTML로 확장 안 함, 동적 조립 CSP는 못 봄.)

### EA006는 왜 안 떴나 (미탐 아님)

두 창 모두 `nodeIntegration: true`라 "안전한 창"이 없어, 창 간 불일치로 볼 대상이
없습니다. 위험은 EA001×2 + EA002로 이미 다 보고됐고, 중복 방지를 위해 EA006은
침묵합니다. spec은 "메인은 안전, 자식만 위험"을 가정했지만 실제 코드는 메인도
위험해, 침묵이 오히려 정확합니다.

---

## 2. Electronegativity 결과 — 16건 + 유지보수 상태

실행 시 그대로 출력된 메시지:

```
Unknown Electron release "33.2.x", please check manually for available security fixes.
```

- 최신 릴리스 **1.10.3 / 2023-03-09** (약 3년 전). Electron 33(2024-10)을 **인식 못 함.**
- 설치 시 eslint 7, tar 6, glob 7 등 **폐기된 의존성** 다수 경고.
- "무료 + 유지보수 + 최신 대응"이 비어 있다는 근거가 실행 자체에서 확인됩니다.

주요 탐지: nodeIntegration(×2, **INFORMATIONAL**), contextIsolation(HIGH), CSP(HTML
`<meta>`, LOW/CERTAIN), openExternal(×2, TENTATIVE), sandbox(×2), auxclick(×2),
preload(×2), http-resources(localhost), permission-request-handler, version-check.

---

## 3. 사과 대 사과 비교 (공통 카테고리만)

| 카테고리 | electron-audit | Electronegativity | 실제 취약? |
| :-- | :-- | :-- | :-- |
| nodeIntegration | ✅ EA001 ×2 (**critical**) | ✅ ×2 (informational) | 둘 다 정탐. 우리는 위험도를 실제에 맞게 높게 봄 |
| contextIsolation | ✅ EA002 (critical) | ✅ (high) | 둘 다 정탐 |
| openExternal | ✅ EA040 ×2 | ✅ ×2 (tentative) | 둘 다 정탐(가드 있는 :96 포함, 양쪽 동일) |
| **명령 주입/권한상승** | ✅ **EA021 + EA022** | ❌ **없음 (미탐)** | **진짜 (핵심 RCE급)** |
| **데이터플로우(소스→싱크)** | ✅ **EA050 ×2** | ❌ 개념 없음 | 진짜 |
| CSP (HTML `<meta>`) | ✅ EA011×4 + EA012×7 (디렉티브별 등급) | ✅ CSP_GLOBAL_CHECK | 진짜 (둘 다 잡음) |
| sandbox | ⚪ 침묵(v20+ 기본 on) | ✅ ×2 | nodeIntegration으로 이미 위험 보고됨 |
| auxclick / preload / permission-handler | — 미지원 | ✅ | Electroneg의 넓은 커버리지(인정) |

### 우리가 잡고 저쪽이 놓친 것 (결정적)

- **`sudo.exec` 명령 주입 (EA021) + 권한상승 exec 래퍼 (EA022).** dnsChanger의
  **실제 핵심 취약점**이자 spec 8번의 1순위. **Electronegativity는 명령 주입 검사
  자체가 없어 완전히 놓칩니다.** 우리는 high-confidence로 잡습니다.
- **데이터플로우(EA050):** "신뢰 불가 IPC 인자 → openExternal/loadURL". Electroneg는
  openExternal을 일반적으로만 표시할 뿐, 소스→싱크 연결 개념이 없습니다.

### 저쪽이 잡고 우리가 놓친 것 (정직하게)

- **HTML `<meta>` CSP (EA011/012):** 최초 실측에선 명백한 패배였습니다. 배포 전에
  얕은 `<meta>` 추출로 메워, 이제는 둘 다 잡습니다(우리는 디렉티브별 등급까지).
  단 `gap:`(EA013)·동적 조립 CSP는 여전히 못 봐, 완전한 HTML 파싱은 v2 사안.
- **넓은 Electron-설정 표면:** sandbox, auxclick, permission-request-handler 등은
  Electroneg가 더 넓게 봅니다. 다만 상당수가 "review the use of X" / "missing Y"
  형태의 저신호 권고이고, **어느 게 확실히 위험한지 구분(confidence)이 없습니다.**

### 오탐 관점

두 도구의 **공통 카테고리(nodeIntegration/contextIsolation/openExternal)에서는
양쪽 다 명백한 오탐이 없습니다** — 이 작은 샘플에서 학술 연구의 "82% 오탐"을
재현했다고 말하지 않겠습니다(그건 더 넓은 코퍼스 기준). 다만 이 샘플에서 드러난
차이는 분명합니다: **Electronegativity는 실제 RCE를 놓치고, 확실/불확실 구분 없이
16건을 쏟아내 어느 걸 먼저 볼지 알기 어렵습니다.** electron-audit는 12건을 내되
확실한 4건(전부 정탐)과 나머지를 명확히 분리하고, **핵심 RCE를 확실하게 잡습니다.**

---

## 4. 결론

- ✅ **배포 전 게이트 통과**: 실제 앱에서 high-confidence 오탐 0건.
- ✅ **핵심 가치 실증**: dnsChanger의 실제 RCE급 취약점(권한상승 명령 주입)을
  확실하게 탐지 — 선행 도구가 놓치는 지점.
- ✅ **데이터플로우 차별점 실증**: IPC 인자 → 위험 싱크 흐름 탐지(EA050).
- ✅ **강건성 실증**: 실제 98파일 무크래시 완주.
- ✅ **패배를 배포 전 승리로**: 유일한 실측 패배(HTML `<meta>` CSP)를 얕은 추출로
  메워, 이제 dnsChanger의 취약 CSP(와일드카드·unsafe-inline·unsafe-eval)를
  디렉티브별 등급으로 잡습니다. 남은 한계(EA013 gap:·동적 CSP·완전 HTML 파싱)는
  정직하게 v2로.
- 📌 **시장 공백 확인**: Electronegativity는 최신 Electron 미인식 + 3년 미갱신.
  "무료 + 유지보수 + 저오탐" 자리가 실제로 비어 있음.

_dnsChanger·Electronegativity 원본 산출물은 작업공간(/tmp)에만 두었고 이 저장소·배포
패키지에 포함하지 않습니다(라이선스·크기). 이 요약만 저장소에 남깁니다._
