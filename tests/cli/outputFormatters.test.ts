import { describe, expect, it } from 'vitest';
import type { Finding, Severity } from '../../src/core/types.js';
import { formatJsonReport } from '../../src/cli/formatters/json.js';
import { formatMarkdownReport } from '../../src/cli/formatters/markdown.js';
import type { ReportMeta } from '../../src/cli/formatters/reportModel.js';

const META: ReportMeta = {
  rootDir: '/project',
  filesScanned: 3,
  filesUnparsable: 1,
  filesAnalysisErrors: 0,
  filesSkippedOversized: 0,
  filesSkippedOutsideRoot: 0,
};

function finding(partial: Partial<Finding> & { ruleId: string; severity: Severity; file: string; line: number }): Finding {
  return { confidence: 'high', target: 'tgt', whyDangerous: 'why', recommendation: 'fix here', ...partial };
}

const FINDINGS: Finding[] = [
  finding({ ruleId: 'EA050', severity: 'medium', confidence: 'heuristic', file: '/project/updater.js', line: 16 }),
  finding({ ruleId: 'EA001', severity: 'critical', file: '/project/main.js', line: 16 }),
];

describe('formatJsonReport', () => {
  it('emits the stable schema with relative paths and severity-ordered findings', () => {
    const parsed = JSON.parse(formatJsonReport(FINDINGS, META));
    expect(parsed.tool).toBe('electron-audit');
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.summary).toMatchObject({ total: 2, filesScanned: 3, filesUnparsable: 1 });
    expect(parsed.summary.bySeverity).toMatchObject({ critical: 1, medium: 1 });
    // Critical first, and absolute paths under root are made relative.
    expect(parsed.findings[0]).toMatchObject({ ruleId: 'EA001', file: 'main.js' });
    expect(parsed.findings[1]).toMatchObject({ ruleId: 'EA050', file: 'updater.js', confidence: 'heuristic' });
  });

  it('surfaces the analysis-error skip count separately from parse failures', () => {
    const parsed = JSON.parse(formatJsonReport(FINDINGS, { ...META, filesAnalysisErrors: 2 }));
    expect(parsed.summary.filesAnalysisErrors).toBe(2);
    expect(parsed.summary.filesUnparsable).toBe(1); // distinct stage, distinct count
  });
});

describe('analysis-error count surfacing (markdown)', () => {
  it('shows the skipped-analysis count in the scan note', () => {
    const md = formatMarkdownReport(FINDINGS, { ...META, filesAnalysisErrors: 2 });
    expect(md).toContain('2 skipped (analysis error)');
  });

  it('omits the note when there are no analysis errors', () => {
    const md = formatMarkdownReport(FINDINGS, { ...META, filesAnalysisErrors: 0 });
    expect(md).not.toContain('analysis error');
  });
});

describe('formatMarkdownReport', () => {
  it('renders severity sections, per-finding why/fix, and marks heuristic findings', () => {
    const md = formatMarkdownReport(FINDINGS, META);
    expect(md).toContain('# electron-audit report');
    expect(md).toContain('## 🔴 Critical (1)');
    expect(md).toContain('## 🟡 Medium (1)');
    expect(md).toContain('### EA001 — tgt');
    expect(md).toContain("**Why it's dangerous:**");
    expect(md).toContain('fix here');
    // heuristic marker present for EA050 only
    expect(md).toContain('### EA050 — tgt `[heuristic]`');
  });

  it('reports a clean project explicitly', () => {
    const md = formatMarkdownReport([], META);
    expect(md).toContain('No issues found');
  });
});
