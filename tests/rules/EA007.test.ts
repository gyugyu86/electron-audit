import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA007 } from '../../src/core/rules/EA007.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures/EA007');

function run(fixtureName: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureName) });
  return new RuleEngine([EA007]).run(scan.files, scan.project);
}

describe('EA007 enableRemoteModule', () => {
  it('flags enableRemoteModule:true on an old Electron (< 14) as high/high-confidence', () => {
    const result = run('vulnerable-old');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA007', severity: 'high', confidence: 'high' });
  });

  it('catches enableRemoteModule:true through a same-file const variable (zonote shape)', () => {
    const result = run('vulnerable-const-var');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA007', severity: 'high', confidence: 'high' });
  });

  it('downgrades to info on Electron 14+ (option removed → dead config, non-gating)', () => {
    const result = run('dead-config-new');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA007', severity: 'info', confidence: 'high' });
  });

  it('reports heuristic when the Electron version is unknown', () => {
    const result = run('unknown-version');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA007', severity: 'high', confidence: 'heuristic' });
  });

  it('stays silent for enableRemoteModule:false / absent', () => {
    expect(run('safe').findings).toHaveLength(0);
  });
});
