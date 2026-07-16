import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import type { Rule } from '../../src/core/types.js';
import { EA002 } from '../../src/core/rules/EA002.js';
import { EA003 } from '../../src/core/rules/EA003.js';
import { EA004 } from '../../src/core/rules/EA004.js';
import { EA005 } from '../../src/core/rules/EA005.js';
import { EA006 } from '../../src/core/rules/EA006.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

function run(rules: Rule[], fixtureRelPath: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureRelPath) });
  return new RuleEngine(rules).run(scan.files, scan.project);
}

describe('EA002 contextIsolation', () => {
  it('flags explicit false as critical, high', () => {
    expect(run([EA002], 'EA002/explicit-false').findings[0]).toMatchObject({
      ruleId: 'EA002',
      severity: 'critical',
      confidence: 'high',
    });
  });

  it('stays silent for explicit true', () => {
    expect(run([EA002], 'EA002/explicit-true').findings).toHaveLength(0);
  });

  it('flags a dynamic value as critical, heuristic', () => {
    expect(run([EA002], 'EA002/dynamic').findings[0]).toMatchObject({
      ruleId: 'EA002',
      severity: 'critical',
      confidence: 'heuristic',
    });
  });
});

describe('EA003 sandbox', () => {
  it('flags explicit false as high, high', () => {
    expect(run([EA003], 'EA003/explicit-false').findings[0]).toMatchObject({
      ruleId: 'EA003',
      severity: 'high',
      confidence: 'high',
    });
  });

  it('flags a dynamic value as high, heuristic', () => {
    expect(run([EA003], 'EA003/dynamic').findings[0]).toMatchObject({
      ruleId: 'EA003',
      severity: 'high',
      confidence: 'heuristic',
    });
  });
});

// Absent contextIsolation/sandbox depend on the target's Electron version:
// contextIsolation secure default since 12, sandbox since 20.
describe('EA002/EA003 version-dependent absence', () => {
  it('new electron (>=20): both absent keys are silent', () => {
    expect(run([EA002], 'webpreferences-version/electron-new').findings).toHaveLength(0);
    expect(run([EA003], 'webpreferences-version/electron-new').findings).toHaveLength(0);
  });

  it('mid electron (12<=v<20): contextIsolation absent silent, sandbox absent heuristic', () => {
    expect(run([EA002], 'webpreferences-version/electron-mid').findings).toHaveLength(0);
    const ea003 = run([EA003], 'webpreferences-version/electron-mid').findings;
    expect(ea003).toHaveLength(1);
    expect(ea003[0]).toMatchObject({ ruleId: 'EA003', severity: 'high', confidence: 'heuristic' });
  });

  it('old electron (<12): both absent keys are heuristic', () => {
    expect(run([EA002], 'webpreferences-version/electron-old').findings[0]).toMatchObject({
      ruleId: 'EA002',
      severity: 'critical',
      confidence: 'heuristic',
    });
    expect(run([EA003], 'webpreferences-version/electron-old').findings[0]).toMatchObject({
      ruleId: 'EA003',
      severity: 'high',
      confidence: 'heuristic',
    });
  });

  it('unknown electron version: both absent keys are heuristic', () => {
    expect(run([EA002], 'webpreferences-version/electron-unknown').findings[0]).toMatchObject({
      ruleId: 'EA002',
      confidence: 'heuristic',
    });
    expect(run([EA003], 'webpreferences-version/electron-unknown').findings[0]).toMatchObject({
      ruleId: 'EA003',
      confidence: 'heuristic',
    });
  });
});

describe('EA004 webSecurity', () => {
  it('flags explicit false as high, high', () => {
    expect(run([EA004], 'EA004/explicit-false').findings[0]).toMatchObject({
      ruleId: 'EA004',
      severity: 'high',
      confidence: 'high',
    });
  });

  it('stays silent when absent (defaults true)', () => {
    expect(run([EA004], 'EA004/safe').findings).toHaveLength(0);
  });
});

describe('EA005 allowRunningInsecureContent', () => {
  it('flags explicit true as medium, high', () => {
    expect(run([EA005], 'EA005/explicit-true').findings[0]).toMatchObject({
      ruleId: 'EA005',
      severity: 'medium',
      confidence: 'high',
    });
  });

  it('stays silent when absent (defaults false)', () => {
    expect(run([EA005], 'EA005/safe').findings).toHaveLength(0);
  });
});

describe('EA006 cross-window mismatch', () => {
  it('flags the inconsistency when a dangerous window coexists with a safe one', () => {
    const result = run([EA006], 'EA006/mismatch');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA006', severity: 'high', confidence: 'high' });
  });

  it('stays silent when all windows are equally dangerous (EA001/EA002 cover those)', () => {
    expect(run([EA006], 'EA006/all-dangerous').findings).toHaveLength(0);
  });

  it('stays silent when all windows are safe', () => {
    expect(run([EA006], 'EA006/all-safe').findings).toHaveLength(0);
  });
});
