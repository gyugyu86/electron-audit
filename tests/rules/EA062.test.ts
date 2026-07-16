import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA062 } from '../../src/core/rules/EA062.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures/EA062');

function run(fixtureName: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureName) });
  return new RuleEngine([EA062]).run(scan.files, scan.project);
}

describe('EA062 Electron version staleness', () => {
  it('flags a clearly outdated electron major (info/heuristic)', () => {
    const result = run('old-version');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA062', severity: 'info', confidence: 'heuristic' });
  });

  it('stays silent for a current electron major', () => {
    expect(run('current-version').findings).toHaveLength(0);
  });

  it('stays silent when the version cannot be determined ("latest")', () => {
    expect(run('unknown-version').findings).toHaveLength(0);
  });
});
