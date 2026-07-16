import { describe, expect, it } from 'vitest';
import type { Finding, NodeRule, Rule, Severity } from '../../src/core/types.js';
import { formatSarifReport } from '../../src/cli/formatters/sarif.js';
import type { ReportMeta } from '../../src/cli/formatters/reportModel.js';

const META: ReportMeta = {
  rootDir: '/project',
  filesScanned: 3,
  filesUnparsable: 0,
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
