import { describe, expect, it } from 'vitest';
import type { Finding, Severity } from '../../src/core/types.js';
import { buildReportModel, formatSeverityCounts } from '../../src/cli/formatters/reportModel.js';

function finding(partial: Partial<Finding> & { ruleId: string; severity: Severity; file: string; line: number }): Finding {
  return {
    confidence: 'high',
    target: 't',
    whyDangerous: 'w',
    recommendation: 'r',
    ...partial,
  };
}

describe('buildReportModel', () => {
  it('groups findings at the same file:line together', () => {
    const model = buildReportModel([
      finding({ ruleId: 'EA001', severity: 'critical', file: 'main.js', line: 16 }),
      finding({ ruleId: 'EA006', severity: 'high', file: 'main.js', line: 16 }),
      finding({ ruleId: 'EA020', severity: 'critical', file: 'other.js', line: 5 }),
    ]);
    const mainGroup = model.groups.find((g) => g.file === 'main.js' && g.line === 16);
    expect(mainGroup?.findings.map((f) => f.ruleId)).toEqual(['EA001', 'EA006']);
  });

  it('orders groups by their most-severe finding, and findings within a group by severity', () => {
    const model = buildReportModel([
      finding({ ruleId: 'EA060', severity: 'info', file: 'a.js', line: 1 }),
      finding({ ruleId: 'EA001', severity: 'critical', file: 'b.js', line: 2 }),
      finding({ ruleId: 'EA041', severity: 'medium', file: 'b.js', line: 2 }),
    ]);
    // b.js:2 (max severity critical) comes before a.js:1 (info)
    expect(model.groups[0]?.file).toBe('b.js');
    // within b.js:2, critical before medium
    expect(model.groups[0]?.findings.map((f) => f.severity)).toEqual(['critical', 'medium']);
    expect(model.groups[1]?.file).toBe('a.js');
  });

  it('counts by severity and omits zero counts in the summary', () => {
    const model = buildReportModel([
      finding({ ruleId: 'EA001', severity: 'critical', file: 'a.js', line: 1 }),
      finding({ ruleId: 'EA002', severity: 'critical', file: 'a.js', line: 2 }),
      finding({ ruleId: 'EA060', severity: 'info', file: 'a.js', line: 3 }),
    ]);
    expect(model.counts).toMatchObject({ critical: 2, high: 0, info: 1 });
    expect(formatSeverityCounts(model.counts)).toBe('critical 2 · info 1');
  });

  it('does not mutate or drop any finding (raw count preserved)', () => {
    const input = [
      finding({ ruleId: 'EA001', severity: 'critical', file: 'a.js', line: 1 }),
      finding({ ruleId: 'EA001', severity: 'critical', file: 'a.js', line: 1 }),
    ];
    const model = buildReportModel(input);
    expect(model.total).toBe(2);
    expect(model.groups[0]?.findings).toHaveLength(2);
  });
});
