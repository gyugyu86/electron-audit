import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { Finding, Rule, Severity } from '../../core/types.js';
import { orderedFindings, buildReportModel, type ReportMeta } from './reportModel.js';

// SARIF 2.1.0 — the format GitHub code scanning ingests natively (results
// show up in the Security tab and as PR annotations). Emitting valid SARIF is
// the whole point, so this stays strictly to the spec's required shape; no
// invented top-level fields.
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFORMATION_URI = 'https://github.com/gyugyu86/electron-audit';

// SARIF has only four levels. critical/high are the tool's actionable-now
// tier -> error; medium -> warning; low/info -> note.
function severityToLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

// GitHub sorts the Security tab by properties["security-severity"] (a 0.0–10.0
// string). Base score by severity; a heuristic finding is knocked down so a
// certain finding always outranks an uncertain one of the same severity. The
// exit-code GATE is separate (high-confidence AND severity≥high) — SARIF shows
// everything, graded; the gate decides CI pass/fail. Don't conflate them.
function securitySeverity(severity: Severity, confidence: 'high' | 'heuristic'): string {
  const base: Record<Severity, number> = { critical: 9, high: 7, medium: 5, low: 3, info: 1 };
  const score = confidence === 'heuristic' ? Math.max(0.5, base[severity] - 2) : base[severity];
  return score.toFixed(1);
}

export function formatSarifReport(
  findings: Finding[],
  meta: ReportMeta,
  allRules: Rule[],
  // The base the artifactLocation URIs are made relative to. GitHub code
  // scanning resolves them against the repo checkout root, which in CI is the
  // process working directory — so cwd, not the scan target, is the correct
  // base. Injectable so the URI-base behavior is unit-tested deterministically.
  cwd: string = process.cwd(),
): string {
  // One reportingDescriptor per distinct rule id (EA041 has two facets that
  // share an id — keep the first).
  const ruleById = new Map<string, Rule>();
  for (const rule of allRules) {
    if (!ruleById.has(rule.id)) {
      ruleById.set(rule.id, rule);
    }
  }
  const rules = [...ruleById.values()];
  const ruleIndex = new Map<string, number>(rules.map((rule, i) => [rule.id, i]));

  const sarifRules = rules.map((rule) => ({
    id: rule.id,
    name: rule.id,
    shortDescription: { text: rule.target },
    fullDescription: { text: rule.whyDangerous },
    help: { text: rule.recommendation },
    defaultConfiguration: { level: severityToLevel(rule.severity) },
    properties: { 'security-severity': securitySeverity(rule.severity, 'high') },
  }));

  const results = orderedFindings(buildReportModel(findings)).map((finding) => ({
    ruleId: finding.ruleId,
    ...(ruleIndex.has(finding.ruleId) ? { ruleIndex: ruleIndex.get(finding.ruleId) } : {}),
    level: severityToLevel(finding.severity),
    message: {
      text: `${finding.confidence === 'heuristic' ? '[heuristic] ' : ''}${finding.target}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toSarifUri(finding.file, meta.rootDir, cwd) },
          // SARIF regions are 1-based; aggregate findings anchored at line 0
          // (package.json manifest checks) clamp to 1.
          region: { startLine: Math.max(1, finding.line) },
        },
      },
    ],
    properties: {
      confidence: finding.confidence,
      'security-severity': securitySeverity(finding.severity, finding.confidence),
    },
  }));

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'electron-audit',
            informationUri: INFORMATION_URI,
            version: readToolVersion(),
            rules: sarifRules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

// GitHub code scanning resolves each result's artifactLocation.uri against the
// repository root (the checkout dir), which in CI is the process working
// directory. So a SARIF URI is made relative to `cwd`, NOT to the scan target:
// scanning a subdirectory (e.g. the self-scan demo scanning
// tests/corpus/synthetic-vuln) then still yields repo-root-relative paths that
// match real files, instead of scan-root-relative basenames that collide with
// same-named files at the repo root (a fixture's `package.json` mis-mapping
// onto the repo's own). When cwd === scanRoot (the common `path: .` case) the
// result is identical to a scan-root-relative path, so this is backward
// compatible. Only SARIF uses cwd as the base — it is the GitHub-targeted
// format; the JSON and Markdown formatters stay scan-root-relative, which reads
// better for a single project's report.
function toSarifUri(file: string, scanRoot: string, cwd: string): string {
  if (!path.isAbsolute(file)) {
    return file;
  }
  const fromCwd = path.relative(cwd, file);
  if (fromCwd !== '' && !fromCwd.startsWith('..') && !path.isAbsolute(fromCwd)) {
    return fromCwd;
  }
  // File is outside cwd (e.g. an absolute scan target run from an unrelated
  // working directory) — fall back to scan-root-relative. Collected files are
  // always within the scan root, so this is a clean relative path except in the
  // exotic symlinked-root case, where it may stay absolute exactly as the
  // pre-cwd behavior did (a separate hardening, out of scope here).
  const fromRoot = path.relative(scanRoot, file);
  return fromRoot.startsWith('..') ? file : fromRoot;
}

// Reads the tool's own version from package.json (../../../package.json holds
// in both dev — dist/cli/formatters — and installed — node_modules/…/dist/…).
function readToolVersion(): string {
  try {
    const pkgUrl = new URL('../../../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(pkgUrl, 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}
