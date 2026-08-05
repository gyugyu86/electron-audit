import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { ALL_RULES } from '../../src/core/rules/index.js';
import { EA020 } from '../../src/core/rules/EA020.js';
import type { Finding } from '../../src/core/types.js';
import type { ReportMeta } from '../../src/cli/formatters/reportModel.js';
import { formatJsonReport } from '../../src/cli/formatters/json.js';
import { formatMarkdownReport } from '../../src/cli/formatters/markdown.js';
import { formatTerminalReport } from '../../src/cli/formatters/terminal.js';
import { formatSarifReport } from '../../src/cli/formatters/sarif.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

const meta: ReportMeta = {
  rootDir: '/project',
  filesScanned: 1,
  filesUnparsable: 0,
  filesAnalysisErrors: 0,
  filesSkippedOversized: 0,
  filesSkippedOutsideRoot: 0,
};

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'EA020',
    severity: 'critical',
    confidence: 'high',
    file: '/project/main.js',
    line: 7,
    target: 'exec(`kill ${pid}`)',
    whyDangerous: 'why',
    recommendation: 'fix',
    ...over,
  };
}

// The engine stamps the role on, from the ScannedFile the finding points at.
// Before this, `role` was computed by the scanner and then read by nobody.
describe('the engine attaches the scanned file role to findings', () => {
  it('carries the role of the file a node-rule finding came from', () => {
    const scan = scanProject({ rootDir: path.join(FIXTURES, 'EA020/vulnerable') });
    const result = new RuleEngine([EA020]).run(scan.files, scan.project);

    expect(result.findings.length).toBeGreaterThan(0);
    for (const found of result.findings) {
      const source = scan.files.find((file) => file.path === found.file);
      expect(found.role).toBe(source?.role);
    }
  });

  // Aggregate rules anchor findings on files that were never scanned as
  // source: package.json (EA060/EA061/EA062) and .html (the CSP rules). Those
  // have no role to attach, and must come out without one rather than with a
  // guessed value — this is the case that keeps `role` optional.
  it('leaves the role absent on a finding anchored to a non-source file', () => {
    const scan = scanProject({ rootDir: path.join(FIXTURES, '../corpus/synthetic-vuln') });
    const result = new RuleEngine(ALL_RULES).run(scan.files, scan.project);

    const scannedPaths = new Set(scan.files.map((file) => file.path));
    const anchoredElsewhere = result.findings.filter((f) => !scannedPaths.has(f.file));

    expect(anchoredElsewhere.length).toBeGreaterThan(0); // the manifest findings exist
    for (const found of anchoredElsewhere) {
      expect(found.role).toBeUndefined();
    }
  });
});

describe('formatters surface the role', () => {
  it('terminal puts it on the location header, once per group', () => {
    const out = formatTerminalReport([finding({ role: 'main' }), finding({ ruleId: 'EA021', role: 'main' })]);
    expect(out).toContain('[main]');
    // One group, one tag — not repeated per finding in the group.
    expect(out.match(/\[main\]/g)).toHaveLength(1);
  });

  it('terminal renders nothing extra when the role is absent', () => {
    const out = formatTerminalReport([finding()]);
    expect(out).not.toContain('[]');
    expect(out).toContain('/project/main.js:7');
  });

  it('json emits the role key, and omits it entirely when absent', () => {
    const withRole = JSON.parse(formatJsonReport([finding({ role: 'preload' })], meta));
    expect(withRole.findings[0].role).toBe('preload');

    const withoutRole = JSON.parse(formatJsonReport([finding()], meta));
    expect('role' in withoutRole.findings[0]).toBe(false); // omitted, not null
    expect(withoutRole.schemaVersion).toBe(1); // additive change keeps the version
  });

  it('markdown tags the location line', () => {
    expect(formatMarkdownReport([finding({ role: 'renderer' })], meta)).toContain('`[renderer]`');
    expect(formatMarkdownReport([finding()], meta)).not.toContain('`[]`');
  });

  it('sarif carries the role in the result property bag next to confidence', () => {
    const withRole = JSON.parse(formatSarifReport([finding({ role: 'main' })], meta, ALL_RULES, '/project'));
    expect(withRole.runs[0].results[0].properties).toMatchObject({ role: 'main', confidence: 'high' });
    // The message text is deliberately untouched — code scanning matches an
    // alert to its previous state partly on that string.
    expect(withRole.runs[0].results[0].message.text).not.toContain('main');

    const withoutRole = JSON.parse(formatSarifReport([finding()], meta, ALL_RULES, '/project'));
    expect('role' in withoutRole.runs[0].results[0].properties).toBe(false);
  });
});
