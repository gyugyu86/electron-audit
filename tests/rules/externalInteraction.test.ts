import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import type { Rule } from '../../src/core/types.js';
import { EA040 } from '../../src/core/rules/EA040.js';
import { EA041Absence, EA041UnconditionalAllow } from '../../src/core/rules/EA041.js';
import { EA042 } from '../../src/core/rules/EA042.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

function run(rules: Rule[], fixtureRelPath: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureRelPath) });
  return new RuleEngine(rules).run(scan.files, scan.project);
}

describe('EA040 shell.openExternal', () => {
  it('stays silent for a static https literal', () => {
    expect(run([EA040], 'EA040/safe-https').findings).toHaveLength(0);
  });

  it('flags a static literal with an unsafe scheme (file:) as high, high-confidence', () => {
    const result = run([EA040], 'EA040/unsafe-file-literal');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA040', severity: 'high', confidence: 'high' });
  });

  it('flags a dynamic argument as high, heuristic (reusing isStaticSafeLiteral)', () => {
    const result = run([EA040], 'EA040/dynamic');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA040', severity: 'high', confidence: 'heuristic' });
  });
});

const EA041_RULES = [EA041Absence, EA041UnconditionalAllow];

describe('EA041 setWindowOpenHandler', () => {
  it('flags an unconditional allow handler as medium, high-confidence (and does not also fire absence)', () => {
    const result = run(EA041_RULES, 'EA041/unconditional-allow');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA041', severity: 'medium', confidence: 'high' });
  });

  it('stays silent for a deny handler', () => {
    expect(run(EA041_RULES, 'EA041/deny').findings).toHaveLength(0);
  });

  it('flags absence as medium, heuristic when an unsafe window exists', () => {
    const result = run(EA041_RULES, 'EA041/absent-unsafe-window');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA041', severity: 'medium', confidence: 'heuristic' });
  });

  it('stays silent for absence when every window is clearly safe', () => {
    expect(run(EA041_RULES, 'EA041/absent-all-safe').findings).toHaveLength(0);
  });

  it('stays silent when there is no BrowserWindow at all', () => {
    expect(run(EA041_RULES, 'EA041/no-window').findings).toHaveLength(0);
  });
});

describe('EA042 loadURL (literal only)', () => {
  it('flags an http remote literal as medium', () => {
    const result = run([EA042], 'EA042/http-remote');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA042', severity: 'medium', confidence: 'high' });
  });

  it('flags an https remote literal as medium', () => {
    const result = run([EA042], 'EA042/https-remote');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA042', severity: 'medium' });
  });

  it('stays silent for a localhost dev URL', () => {
    expect(run([EA042], 'EA042/localhost').findings).toHaveLength(0);
  });

  it('stays silent for a dynamic URL (that is EA050/F-group territory)', () => {
    expect(run([EA042], 'EA042/dynamic').findings).toHaveLength(0);
  });
});
