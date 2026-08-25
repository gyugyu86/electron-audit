import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { readFileSync } from 'node:fs';
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
    expect(result.findings[0]?.target).toContain('file path');
  });

  // A wrapper package re-exporting the fs API is the same sink as fs itself.
  // Not recognizing one is a miss nothing reports: the scan completes, the
  // file looks clean, and the reason is that the sink was never identified.
  // One entry per recognized wrapper, so removing any single one fails only
  // its own case.
  it('C: ipc handler arg -> fs sink reached through fs-extra fires', () => {
    const result = run('EA050/vulnerable-ipc-fs-extra');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA050', severity: 'medium', confidence: 'heuristic' });
    expect(result.findings[0]?.target).toContain('file path');
  });

  it('C: ipc handler arg -> fs sink reached through graceful-fs fires', () => {
    const result = run('EA050/vulnerable-ipc-graceful-fs');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA050', severity: 'medium', confidence: 'heuristic' });
    expect(result.findings[0]?.target).toContain('file path');
  });

  // fs-extra's own helpers are sinks on the same terms as the vanilla names.
  // Each case pins the finding to the LINE its own helper is called on, so
  // dropping one name from the list fails that case and leaves the others
  // green — asserting a total would make every case fail together and prove
  // nothing about which name did the work.
  describe('fs-extra helpers are path sinks', () => {
    const fixtureDir = path.join(FIXTURES, 'EA050/vulnerable-ipc-fs-extra-helpers');
    const source = readFileSync(path.join(fixtureDir, 'main.js'), 'utf8').split('\n');
    const lineOf = (method: string): number =>
      source.findIndex((line) => line.includes(`fs.${method}(`)) + 1;

    const HELPERS = [
      'outputFile', 'outputFileSync', 'outputJson', 'outputJsonSync',
      'writeJson', 'writeJsonSync', 'readJson', 'readJsonSync',
      'remove', 'removeSync', 'emptyDir', 'emptyDirSync',
      'move', 'moveSync', 'copy', 'copySync',
    ];

    for (const method of HELPERS) {
      it(`reports the ipc-driven ${method} call`, () => {
        const findings = run('EA050/vulnerable-ipc-fs-extra-helpers').findings;
        const atLine = findings.filter((finding) => finding.line === lineOf(method));
        expect(atLine).toHaveLength(1);
        expect(atLine[0]).toMatchObject({ ruleId: 'EA050', severity: 'medium', confidence: 'heuristic' });
        expect(atLine[0]?.target).toContain('file path');
      });
    }
  });

  it('stays silent for a static path through an fs-extra helper', () => {
    expect(run('EA050/safe-fs-extra-helper-static').findings).toHaveLength(0);
  });

  // The names above are ordinary words — `remove` is called hundreds of times
  // on non-filesystem objects across the measured corpora. The sink check
  // resolves the receiver to a filesystem module first, so those stay silent;
  // this is what makes listing a name like `remove` safe at all.
  it('does not treat a same-named method on a non-filesystem object as a sink', () => {
    expect(run('EA050/safe-nonfs-same-method-name').findings).toHaveLength(0);
  });

  // Recognizing the module must not turn every call through it into a
  // finding — the taint check still has to reach the path argument.
  it('stays silent for a static path through a recognized wrapper', () => {
    expect(run('EA050/safe-fs-wrapper-static').findings).toHaveLength(0);
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
