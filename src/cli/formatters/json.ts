import path from 'node:path';
import type { Finding } from '../../core/types.js';
import { buildReportModel, orderedFindings, type ReportMeta } from './reportModel.js';

// Stable machine-readable schema for CI and downstream tools. schemaVersion
// is bumped only on a breaking field change. Findings are emitted in report
// order (severity, then location) so the output is deterministic. File paths
// are relative to the scanned root for portability.
export function formatJsonReport(findings: Finding[], meta: ReportMeta): string {
  const model = buildReportModel(findings);

  const payload = {
    tool: 'electron-audit',
    schemaVersion: 1,
    summary: {
      total: model.total,
      bySeverity: model.counts,
      filesScanned: meta.filesScanned,
      filesUnparsable: meta.filesUnparsable,
      filesAnalysisErrors: meta.filesAnalysisErrors,
      filesSkippedOversized: meta.filesSkippedOversized,
      filesSkippedOutsideRoot: meta.filesSkippedOutsideRoot,
    },
    findings: orderedFindings(model).map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      confidence: finding.confidence,
      file: relativize(meta.rootDir, finding.file),
      line: finding.line,
      // Sits with the location it is derived from. The key is OMITTED (not
      // null) when the finding has no role, so a consumer can test presence
      // rather than distinguish "absent" from "explicitly nothing". Adding an
      // optional key is additive, so schemaVersion stays 1 — it is bumped only
      // on a breaking field change.
      ...(finding.role ? { role: finding.role } : {}),
      target: finding.target,
      whyDangerous: finding.whyDangerous,
      recommendation: finding.recommendation,
    })),
  };

  return JSON.stringify(payload, null, 2);
}

function relativize(rootDir: string, file: string): string {
  if (!path.isAbsolute(file)) {
    return file;
  }
  const relative = path.relative(rootDir, file);
  return relative.startsWith('..') ? file : relative;
}
