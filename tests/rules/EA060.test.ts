import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA060 } from '../../src/core/rules/EA060.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures/EA060');

function run(fixtureName: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureName) });
  return new RuleEngine([EA060]).run(scan.files, scan.project);
}

describe('EA060 telemetry/analytics SDK detection', () => {
  it('flags each imported telemetry SDK once, at the import location (info/heuristic)', () => {
    const result = run('with-telemetry-import');
    // react-ga4 and @sentry/electron -> 2 distinct SDKs.
    expect(result.findings).toHaveLength(2);
    expect(result.findings.every((f) => f.ruleId === 'EA060' && f.severity === 'info' && f.confidence === 'heuristic')).toBe(true);
    expect(result.findings.every((f) => f.file.endsWith('main.js') && f.line > 0)).toBe(true);
  });

  it('flags a telemetry SDK declared in deps but not imported, anchored at package.json', () => {
    const result = run('with-telemetry-dep-only');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.file.endsWith('package.json')).toBe(true);
  });

  it('stays silent when no telemetry SDK is present', () => {
    expect(run('no-telemetry').findings).toHaveLength(0);
  });
});
