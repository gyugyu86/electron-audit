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
  EA040,
  EA041Absence,
  EA041UnconditionalAllow,
  EA042,
  EA050,
  EA060,
  EA061,
  EA062,
];
