import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { ALL_RULES } from '../../src/core/rules/index.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));

// Runs the full current rule set against a whole corpus project and returns
// a normalized, sorted finding list stable enough to snapshot. `corpusDir`
// is just a directory name under tests/corpus/ — swapping in a real
// dnsChanger checkout later, or adding one, needs no change here.
function runCorpus(corpusDirName: string) {
  const root = path.join(dirname, corpusDirName);
  const scan = scanProject({ rootDir: root });
  const result = new RuleEngine(ALL_RULES).run(scan.files, scan.project);

  const findings = result.findings
    .map((f) => ({
      ruleId: f.ruleId,
      severity: f.severity,
      confidence: f.confidence,
      file: path.relative(root, f.file),
      line: f.line,
    }))
    .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));

  return { findings, filesScanned: result.filesScanned, filesUnparsable: result.filesUnparsable };
}

// Baseline approved 2026-07-16: EA001 main.js:16, EA020 main.js:57,
// EA021 main.js:63 (no duplicate EA020 for that site), EA020 updater.js:16.
//
// updater.js:16 is EA020 only for now. When F그룹 EA050 (remote data flowing
// into a sink; medium/heuristic) lands, that site must ALSO emit a medium
// EA050 finding — EA020's rationale (syntactic: interpolation into a shell
// string) and EA050's (dataflow: untrusted remote value reaches the sink)
// are orthogonal, so BOTH are reported by design. Do not suppress one for
// the other when updating this snapshot.
describe('corpus regression: synthetic-vuln', () => {
  it('matches the approved findings snapshot', () => {
    const { findings } = runCorpus('synthetic-vuln');
    expect(findings).toMatchSnapshot();
  });
});
