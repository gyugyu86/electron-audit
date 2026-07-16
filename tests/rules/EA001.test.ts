import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA001 } from '../../src/core/rules/EA001.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(dirname, '../fixtures/EA001');

function runEA001(fixtureName: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES_ROOT, fixtureName) });
  return new RuleEngine([EA001]).run(scan.files);
}

describe('EA001 nodeIntegration:true', () => {
  it('flags an explicit nodeIntegration:true as critical, high-confidence', () => {
    const result = runEA001('vulnerable');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA001', severity: 'critical', confidence: 'high' });
  });

  it('reports nothing for a safe window (nodeIntegration:false + preload)', () => {
    const result = runEA001('safe');
    expect(result.findings).toHaveLength(0);
  });

  it('flags a dynamic nodeIntegration value as critical, heuristic-confidence', () => {
    const result = runEA001('dynamic');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA001', severity: 'critical', confidence: 'heuristic' });
  });
});
