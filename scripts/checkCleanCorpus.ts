// Tier-1 clean-corpus FP gate: scans the pinned third-party checkouts with
// the FULL rule set and fails (exit 1) if any finding would fail the tool's
// own default CI gate. The criterion is not restated here — each finding is
// classified by running it through cli/exitCode.ts's computeExitCode in
// 'default' mode, so this gate can never drift from what `electron-audit`
// itself would fail a consumer's build on (high-confidence AND severity
// critical/high; heuristic and medium/low/info findings are allowed).
//
// Missing checkouts are a SKIP, not a failure: `npm test` stays offline and
// nobody is blocked for not having run `npm run corpus:fetch`. CI runs the
// fetch first, so there a missing checkout can't slip through as a skip.
import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../src/core/scanner.js';
import { RuleEngine } from '../src/core/ruleEngine.js';
import { ALL_RULES } from '../src/core/rules/index.js';
import { parseSource } from '../src/core/parser.js';
import { computeExitCode } from '../src/cli/exitCode.js';
import type { Finding } from '../src/core/types.js';

interface Tier1Checkout {
  name: string;
  url: string;
  sha: string;
  license: string;
}
interface Tier1Config {
  checkoutsDir: string;
  checkouts: Tier1Checkout[];
}

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(
  readFileSync(path.join(rootDir, 'tests/corpus/clean/tier1.json'), 'utf8'),
) as Tier1Config;

// A finding gates iff the tool's own default exit-code policy would fail on
// it alone — the exact reuse requested by the corpus design.
const isGating = (finding: Finding): boolean => computeExitCode([finding], 'default') !== 0;

function snippet(file: string, line: number): string {
  if (line <= 0) {
    return '      (project-level finding — no single anchor line)';
  }
  const lines = readFileSync(file, 'utf8').split('\n');
  const from = Math.max(1, line - 3);
  const to = Math.min(lines.length, line + 3);
  const out: string[] = [];
  for (let n = from; n <= to; n += 1) {
    out.push(`      ${n === line ? '>' : ' '} ${String(n).padStart(4)} | ${lines[n - 1] ?? ''}`);
  }
  return out.join('\n');
}

let scanned = 0;
let gatingTotal = 0;

for (const { name, url, sha } of config.checkouts) {
  const dir = path.join(rootDir, config.checkoutsDir, name);
  if (!existsSync(dir)) {
    console.log(`SKIP ${name}: no checkout at ${path.relative(rootDir, dir)} (run \`npm run corpus:fetch\`)`);
    continue;
  }
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  if (head !== sha) {
    console.error(`FAIL ${name}: checkout at ${head.slice(0, 7)} but pin is ${sha.slice(0, 7)} — run \`npm run corpus:fetch\``);
    process.exitCode = 1;
    continue;
  }
  scanned += 1;

  const started = Date.now();
  const scan = scanProject({ rootDir: dir });
  const result = new RuleEngine(ALL_RULES).run(scan.files, scan.project);
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  const gating = result.findings.filter(isGating);
  const others = result.findings.filter((finding) => !isGating(finding));
  gatingTotal += gating.length;

  console.log(`\n=== ${url.replace(/\.git$/, '')} @ ${sha} ===`);
  console.log(
    `files scanned: ${result.filesScanned}, unparsable: ${result.filesUnparsable}, elapsed: ${elapsed}s`,
  );
  console.log(`gating findings (high-confidence critical/high, must be 0): ${gating.length}`);
  console.log(`other findings (allowed): ${others.length}`);

  for (const finding of gating) {
    console.log(`\n  GATE VIOLATION ${finding.ruleId} ${finding.severity}/${finding.confidence}`);
    console.log(`    ${path.relative(dir, finding.file)}:${finding.line}`);
    console.log(`    target: ${finding.target}`);
    console.log(snippet(finding.file, finding.line));
  }

  if (others.length > 0) {
    const byRule = new Map<string, number>();
    for (const finding of others) {
      byRule.set(finding.ruleId, (byRule.get(finding.ruleId) ?? 0) + 1);
    }
    const summary = [...byRule.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([ruleId, count]) => `${ruleId}×${count}`)
      .join(', ');
    console.log(`  other findings by rule: ${summary}`);
  }

  // Only when the engine reported unparsable files, identify which — a
  // second parse pass is wasteful in the common all-parse case.
  if (result.filesUnparsable > 0) {
    console.log('  unparsable files:');
    for (const file of scan.files) {
      if (!parseSource(file.content, file.path)) {
        console.log(`    ${path.relative(dir, file.path)}`);
      }
    }
  }
}

if (scanned === 0) {
  console.log('\nSKIP: no Tier-1 checkouts present — nothing scanned (run `npm run corpus:fetch`).');
  process.exit(0);
}
if (gatingTotal > 0) {
  console.error(
    `\nFAIL: ${gatingTotal} gating finding(s) in the clean corpus. Do NOT weaken rules to pass this gate — triage each finding first (see tests/corpus/clean/PROVENANCE.md).`,
  );
  process.exit(1);
}
console.log('\nOK: clean corpus produced no gating findings.');
