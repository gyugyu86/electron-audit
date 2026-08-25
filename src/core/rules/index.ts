import type { Rule } from '../types.js';
import { EA001 } from './EA001.js';
import { EA002 } from './EA002.js';
import { EA003 } from './EA003.js';
import { EA004 } from './EA004.js';
import { EA005 } from './EA005.js';
import { EA006 } from './EA006.js';
import { EA007 } from './EA007.js';
import { EA010 } from './EA010.js';
import { EA011 } from './EA011.js';
import { EA012 } from './EA012.js';
import { EA013 } from './EA013.js';
import { EA020 } from './EA020.js';
import { EA021 } from './EA021.js';
import { EA022 } from './EA022.js';
import { EA031 } from './EA031.js';
import { EA040 } from './EA040.js';
import { EA041Absence, EA041UnconditionalAllow } from './EA041.js';
import { EA042 } from './EA042.js';
import { EA050 } from './EA050.js';
import { EA060 } from './EA060.js';
import { EA061 } from './EA061.js';
import { EA062 } from './EA062.js';

// Single source of truth for "every rule this build implements" — the CLI
// and the corpus regression snapshot both register against this instead of
// keeping their own hand-maintained lists that would drift as groups land.
// EA041 has two facets (absence + unconditional-allow) that both emit
// ruleId 'EA041'.
//
// D group (IPC): only EA031 is implemented. The other two reserved numbers are
// not held back for want of a signal — measurement said each would be wrong in
// its own way:
// - EA030 (IPC handler argument reaching a sink unvalidated) IS ALREADY
//   SHIPPED, as EA050. That rule's source family C is precisely "a parameter
//   after `event` of an ipcMain.handle/on or ipcRenderer.on callback", flowing
//   to the command, external-URL and filesystem sinks. Adding EA030 would
//   report the same call sites twice under two ids. Measured across the
//   corpora: of 309 inline handlers carrying such a parameter, 6 reach a sink
//   inside the same function scope — the limit of this tool's dataflow, since
//   270 of the rest hand the parameter to another function — and EA050 already
//   reports them.
// - EA032 (renderer API exposed on `window` without contextBridge) would be
//   redundant exactly when it matters and wrong the rest of the time. A
//   preload writing to `window` exposes nothing while contextIsolation is on,
//   because that window is an isolated world the page never sees; when it is
//   off, EA002 already reports the isolation itself, which is the actual
//   defect. Measured on a modern app where isolation defaults on, 36 of 37
//   candidate writes were to an isolated world, and 16 more were shims
//   (`window.onerror`, `window.setImmediate`) or test files rather than any
//   API surface.
//
// EA031 reads only an object literal written inline at the exposeInMainWorld
// call. A pass-through held in a const is not reported — a miss taken on
// purpose: reading those was measured and every case it reached had already
// checked the channel against an allowlist, which is the fix this rule
// recommends. Recognizing such a guard, the way EA040 recognizes a dominating
// scheme guard, is what would make the wider read safe, and is a v2 candidate.
//
// Deferred (held rather than shipped as noisy heuristics):
// - EA043 (will-navigate / webview guard absence). Its strongest signal — a
//   <webview> tag — lives in HTML, which this tool does not parse, and
//   "absence of a will-navigate handler" alone isn't a vulnerability in a
//   well-configured app.
// - EA051 (auto-update signature/verification). ** V2 CANDIDATE #1 — the risk
//   is real and important, NOT dismissed. ** electron-updater signature-
//   verification bypass is a known RCE class (see Doyensec's electron-updater
//   research): an app that fetches updates over an insecure/http feed or with
//   Windows signature verification disabled can be served a malicious update.
//   It is deferred for ONE reason only — a LOW-FALSE-POSITIVE static signal is
//   hard: electron-updater verifies signatures by default on the platforms
//   that support it, and the dangerous states (http feed, disabled
//   verifyUpdateCodeSignature, forceDevUpdateConfig in production) appear in
//   many different config shapes. Shipping it now would mean noise on
//   correctly-configured apps, which this tool refuses. Revisit first in v2
//   with a precise signal (e.g. an explicit http provider URL, or an
//   explicitly-falsy signature-check flag).
// A static, low-false-positive formulation for these wasn't available yet.
export const ALL_RULES: Rule[] = [
  EA001,
  EA002,
  EA003,
  EA004,
  EA005,
  EA006,
  EA007,
  EA010,
  EA011,
  EA012,
  EA013,
  EA020,
  EA021,
  EA022,
  EA031,
  EA040,
  EA041Absence,
  EA041UnconditionalAllow,
  EA042,
  EA050,
  EA060,
  EA061,
  EA062,
];
