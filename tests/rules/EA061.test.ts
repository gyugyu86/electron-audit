import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA061 } from '../../src/core/rules/EA061.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures/EA061');

function run(fixtureName: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureName) });
  return new RuleEngine([EA061]).run(scan.files, scan.project);
}

describe('EA061 electron-builder code signing absence', () => {
  it('flags an electron-builder project with no signing config (low/heuristic)', () => {
    const result = run('builder-no-signing');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA061', severity: 'low', confidence: 'heuristic' });
  });

  it('stays silent when signing is configured (mac.identity)', () => {
    expect(run('builder-with-signing').findings).toHaveLength(0);
  });

  it('stays silent when electron-builder is not used at all', () => {
    expect(run('no-builder').findings).toHaveLength(0);
  });

  it('stays silent when config lives only in an unparseable file (cannot verify absence)', () => {
    expect(run('builder-yaml-only').findings).toHaveLength(0);
  });
});
