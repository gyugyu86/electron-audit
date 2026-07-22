import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Finding, NodeRule, Rule, Severity } from '../../src/core/types.js';
import { formatSarifReport } from '../../src/cli/formatters/sarif.js';
import type { ReportMeta } from '../../src/cli/formatters/reportModel.js';

const META: ReportMeta = {
  rootDir: '/project',
  filesScanned: 3,
  filesUnparsable: 0,
  filesAnalysisErrors: 0,
  filesSkippedOversized: 0,
  filesSkippedOutsideRoot: 0,
};

function rule(id: string, severity: Severity): NodeRule {
  return { id, kind: 'node', severity, target: `${id} target`, whyDangerous: 'why', recommendation: 'fix', check: () => [] };
}

function finding(partial: Partial<Finding> & { ruleId: string; severity: Severity; file: string; line: number }): Finding {
  return { confidence: 'high', target: 'tgt', whyDangerous: 'why', recommendation: 'fix', ...partial };
}

const RULES: Rule[] = [rule('EA001', 'critical'), rule('EA050', 'medium'), rule('EA062', 'info')];

describe('formatSarifReport', () => {
  it('produces a valid SARIF 2.1.0 skeleton with a driver and deduped rules', () => {
    const sarif = JSON.parse(formatSarifReport([], META, [...RULES, rule('EA001', 'critical')]));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif');
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe('electron-audit');
    // EA001 listed once despite the duplicate
    expect(driver.rules.filter((r: { id: string }) => r.id === 'EA001')).toHaveLength(1);
    expect(driver.rules.every((r: { id: string; shortDescription?: { text: string } }) => r.id && r.shortDescription?.text)).toBe(true);
  });

  it('maps severity to SARIF level and grades security-severity (heuristic lowered)', () => {
    const sarif = JSON.parse(
      formatSarifReport(
        [
          finding({ ruleId: 'EA001', severity: 'critical', file: '/project/main.js', line: 10 }),
          finding({ ruleId: 'EA050', severity: 'medium', confidence: 'heuristic', file: '/project/x.js', line: 4 }),
          finding({ ruleId: 'EA062', severity: 'info', confidence: 'heuristic', file: '/project/package.json', line: 0 }),
        ],
        META,
        RULES,
        // cwd == scan root here, so URIs are deterministically scan-root-relative.
        '/project',
      ),
    );
    const results = sarif.runs[0].results as Array<{
      ruleId: string;
      level: string;
      properties: { confidence: string; 'security-severity': string };
      message: { text: string };
      locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }>;
    }>;

    const byRule = (ruleId: string): (typeof results)[number] => {
      const found = results.find((r) => r.ruleId === ruleId);
      if (!found) {
        throw new Error(`no SARIF result for ${ruleId}`);
      }
      return found;
    };

    const critical = byRule('EA001');
    expect(critical.level).toBe('error');
    expect(critical.properties['security-severity']).toBe('9.0');

    const heuristicMedium = byRule('EA050');
    expect(heuristicMedium.level).toBe('warning');
    expect(heuristicMedium.properties['security-severity']).toBe('3.0'); // 5 - 2
    expect(heuristicMedium.message.text.startsWith('[heuristic]')).toBe(true);

    // aggregate finding at line 0 -> clamped to 1; path relativized
    const info = byRule('EA062');
    expect(info.level).toBe('note');
    expect(info.locations[0].physicalLocation.region.startLine).toBe(1);
    expect(info.locations[0].physicalLocation.artifactLocation.uri).toBe('package.json');
  });

  it('references each result to a rule by ruleIndex', () => {
    const sarif = JSON.parse(
      formatSarifReport([finding({ ruleId: 'EA050', severity: 'medium', file: '/project/x.js', line: 4 })], META, RULES),
    );
    const driver = sarif.runs[0].tool.driver;
    const result = sarif.runs[0].results[0];
    expect(driver.rules[result.ruleIndex].id).toBe('EA050');
  });
});

// The artifactLocation.uri is made relative to cwd (the checkout root in CI),
// not the scan target, so a subdirectory scan still produces repo-root-relative
// paths GitHub can match. cwd is injected here so every case is deterministic —
// these mirror the six approved scenarios one-for-one; no reliance on the real
// process.cwd() (that would be flaky).
describe('formatSarifReport uri base (cwd-relative)', () => {
  const metaWith = (rootDir: string): ReportMeta => ({
    rootDir,
    filesScanned: 1,
    filesUnparsable: 0,
    filesAnalysisErrors: 0,
    filesSkippedOversized: 0,
    filesSkippedOutsideRoot: 0,
  });

  const uriOf = (rootDir: string, file: string, cwd: string): string => {
    const sarif = JSON.parse(
      formatSarifReport([finding({ ruleId: 'EA001', severity: 'critical', file, line: 10 })], metaWith(rootDir), RULES, cwd),
    );
    return sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  };

  it('CI self-scan: a subdirectory scan yields a repo-root-relative uri (cwd = repo root)', () => {
    expect(uriOf('/repo/tests/corpus/synthetic-vuln', '/repo/tests/corpus/synthetic-vuln/main.js', '/repo')).toBe(
      'tests/corpus/synthetic-vuln/main.js',
    );
  });

  it('CI self-scan: a manifest finding maps to the real subdir package.json, not the repo-root one', () => {
    expect(uriOf('/repo/tests/corpus/synthetic-vuln', '/repo/tests/corpus/synthetic-vuln/package.json', '/repo')).toBe(
      'tests/corpus/synthetic-vuln/package.json',
    );
  });

  it('consumer path=.: scan root equals repo root — identical to scan-root-relative (backward compatible)', () => {
    expect(uriOf('/repo', '/repo/main.js', '/repo')).toBe('main.js');
  });

  it('consumer path=subdir: a monorepo package path stays repo-root-relative', () => {
    expect(uriOf('/repo/packages/app', '/repo/packages/app/main.js', '/repo')).toBe('packages/app/main.js');
  });

  // The one intended behavior change: running locally from an ANCESTOR of the
  // project makes the uri invoke-relative rather than project-relative. This is
  // correct for SARIF's cwd-based contract — pinned so it is not later mistaken
  // for a regression and reverted.
  it('local run from an ancestor cwd: uri is invoke-relative (proj/app/main.js), by design', () => {
    expect(uriOf('/Users/me/proj/app', '/Users/me/proj/app/main.js', '/Users/me')).toBe('proj/app/main.js');
  });

  it('local run from an unrelated cwd: falls back to scan-root-relative, never ../ or absolute', () => {
    const uri = uriOf('/Users/me/proj/app', '/Users/me/proj/app/main.js', '/tmp/x');
    expect(uri).toBe('main.js');
    expect(path.isAbsolute(uri)).toBe(false);
    expect(uri.startsWith('..')).toBe(false);
  });
});
