import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA050 } from '../../src/core/rules/EA050.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

function run(fixtureRelPath: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureRelPath) });
  return new RuleEngine([EA050]).run(scan.files, scan.project);
}

describe('EA050 untrusted deserialization / external input -> sink', () => {
  it('B: fetch -> .json() -> exec (same scope) fires medium/heuristic', () => {
    const result = run('EA050/vulnerable-fetch-exec');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA050', severity: 'medium', confidence: 'heuristic' });
  });

  it('A: JSON.parse -> exec (same scope) fires', () => {
    const result = run('EA050/vulnerable-jsonparse-exec');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA050', severity: 'medium', confidence: 'heuristic' });
  });

  it('C: ipc handler arg -> fs path sink fires, tagged as a path sink', () => {
    const result = run('EA050/vulnerable-ipc-fs');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.target).toContain('파일 경로');
  });

  it('stays silent for JSON.parse of a local fs read (local config, not external)', () => {
    expect(run('EA050/safe-local-fs-config').findings).toHaveLength(0);
  });

  it('stays silent when the untrusted value is only a whitelist key and the sink gets a trusted value', () => {
    expect(run('EA050/safe-whitelist').findings).toHaveLength(0);
  });

  it('stays silent for a member of the ipc event object (event is not a source)', () => {
    expect(run('EA050/safe-ipc-event-object').findings).toHaveLength(0);
  });

  // Locks the accepted false-negative boundary: cross-function flow is not
  // tracked. If someone widens the scope and reintroduces cross-function
  // tracking (with its false positives), this test fails.
  it('does NOT fire when source and sink are in different functions', () => {
    expect(run('EA050/negative-cross-function').findings).toHaveLength(0);
  });
});
