import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { ALL_RULES } from '../../src/core/rules/index.js';
import { computeExitCode } from '../../src/cli/exitCode.js';
import { formatJsonReport } from '../../src/cli/formatters/json.js';
import { formatMarkdownReport } from '../../src/cli/formatters/markdown.js';
import { formatSarifReport } from '../../src/cli/formatters/sarif.js';
import { messages } from '../../src/cli/messages.js';
import type { ReportMeta } from '../../src/cli/formatters/reportModel.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(dirname, '../fixtures/unsupported-extensions');

let scratchDir: string | undefined;
afterEach(() => {
  if (scratchDir) {
    fs.rmSync(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

function metaFor(root: string): { meta: ReportMeta; findings: ReturnType<RuleEngine['run']>['findings'] } {
  const scan = scanProject({ rootDir: root });
  const result = new RuleEngine(ALL_RULES).run(scan.files, scan.project);
  return {
    findings: result.findings,
    meta: {
      rootDir: root,
      filesScanned: result.filesScanned,
      filesUnparsable: result.filesUnparsable,
      filesAnalysisErrors: result.filesAnalysisErrors,
      filesSkippedOversized: scan.skippedOversized,
      filesSkippedOutsideRoot: scan.skippedOutsideRoot,
      filesSkippedUnsupported: scan.skippedUnsupported,
    },
  };
}

// A single-file component is dropped by the extension filter before the parser,
// so until now it appeared in no count at all — the report just showed fewer
// files. It is now counted, and only counted: never opened.
describe('single-file components are counted, not read', () => {
  it('counts .vue and .svelte files, and nothing else that is merely unsupported', () => {
    const scan = scanProject({ rootDir: FIXTURE });
    // App.vue + Panel.vue + Widget.svelte; README.md is unsupported too but is
    // not a source format, so it must not inflate the number.
    expect(scan.skippedUnsupported).toBe(3);
    expect(scan.files.map((f) => path.basename(f.path))).toEqual(['main.js']);
  });

  // The whole point of a separate counter. Three files that all end up
  // unanalyzed, for three different reasons, at three different stages — each
  // must land in its own count and nowhere else, or "why is this file
  // missing" becomes untraceable.
  it('keeps the count apart from parse failures and analysis errors', () => {
    scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ea-unsupported-'));
    fs.writeFileSync(path.join(scratchDir, 'View.vue'), '<script>export default {}</script>\n');
    fs.writeFileSync(path.join(scratchDir, 'broken.js'), 'const { BrowserWindow = require("electron");\n');
    fs.writeFileSync(
      path.join(scratchDir, 'crash.js'),
      "import { helper } from './helper.js';\nfunction helper() {\n  return 1;\n}\nhelper();\n",
    );
    fs.writeFileSync(
      path.join(scratchDir, 'vulnerable.js'),
      "const { BrowserWindow } = require('electron');\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
    );

    const { meta, findings } = metaFor(scratchDir);
    expect(meta.filesSkippedUnsupported).toBe(1); // View.vue — never opened
    expect(meta.filesUnparsable).toBe(1); // broken.js — opened, failed to parse
    expect(meta.filesAnalysisErrors).toBe(1); // crash.js — parsed, threw in traverse
    expect(meta.filesScanned).toBe(3); // the .vue is not a scanned file
    expect(findings.some((f) => f.ruleId === 'EA001')).toBe(true); // detection untouched
  });

  it('reports zero when a project has none', () => {
    const scan = scanProject({ rootDir: path.join(dirname, '../fixtures/EA020/vulnerable') });
    expect(scan.skippedUnsupported).toBe(0);
  });

  // Counting must change nothing about what is found or whether a build fails.
  // The exit code is computed from findings alone — the count is not an input.
  it('leaves findings and the exit code exactly as they were', () => {
    const { findings } = metaFor(FIXTURE);
    expect(findings.filter((f) => f.ruleId === 'EA001')).toHaveLength(1);
    expect(computeExitCode(findings, 'default')).toBe(1);
    expect(computeExitCode(findings, 'none')).toBe(0);
  });
});

describe('the count reaches the report', () => {
  it('json carries it as a number, zero included, without a schema bump', () => {
    const withSome = JSON.parse(formatJsonReport(metaFor(FIXTURE).findings, metaFor(FIXTURE).meta));
    expect(withSome.summary.filesSkippedUnsupported).toBe(3);
    expect(withSome.schemaVersion).toBe(1);

    const none = metaFor(path.join(dirname, '../fixtures/EA020/vulnerable'));
    const withNone = JSON.parse(formatJsonReport(none.findings, none.meta));
    expect(withNone.summary.filesSkippedUnsupported).toBe(0); // present, not omitted
  });

  // Same convention as the other skip counts: said when non-zero, silent at
  // zero, so a project without components sees no extra line.
  it('markdown states what went unanalyzed, and only when there is something', () => {
    const some = metaFor(FIXTURE);
    expect(formatMarkdownReport(some.findings, some.meta)).toContain(messages.countUnsupported(3));

    const none = metaFor(path.join(dirname, '../fixtures/EA020/vulnerable'));
    expect(formatMarkdownReport(none.findings, none.meta)).not.toContain('single-file component');
  });

  it('phrases the note as what is outside the scan, without asserting the file is a renderer', () => {
    const note = messages.countUnsupported(3);
    expect(note).toContain('not analyzed');
    expect(note).toContain('.vue/.svelte');
    expect(note).toMatch(/if your renderer/); // conditional, not a claim
    expect(messages.countUnsupported(1)).toContain('1 single-file component ('); // singular
  });

  // SARIF carries no scan counts at all today — not unparsable, not analysis
  // errors — so adding this one alone would be the odd one out. Pinned so the
  // decision is deliberate rather than an oversight.
  it('sarif is left alone, consistent with the other scan counts', () => {
    const some = metaFor(FIXTURE);
    const sarif = formatSarifReport(some.findings, some.meta, ALL_RULES, FIXTURE);
    expect(sarif).not.toContain('filesSkippedUnsupported');
    expect(sarif).not.toContain('single-file component');
  });
});
