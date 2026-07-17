import path from 'node:path';
import type { Finding, Severity } from '../../core/types.js';
import { buildReportModel, formatSeverityCounts, orderedFindings, SEVERITY_ORDER, type ReportMeta } from './reportModel.js';
import { messages } from '../messages.js';

const SEVERITY_HEADING: Record<Severity, string> = {
  critical: '🔴 Critical',
  high: '🟠 High',
  medium: '🟡 Medium',
  low: '🔵 Low',
  info: '⚪ Info',
};

// Human-facing report. The educational payload — "why dangerous" + a fix
// example per finding — is this tool's core value, so it's front and centre.
// Grouped into severity sections (most severe first); within a section,
// findings keep report order.
export function formatMarkdownReport(findings: Finding[], meta: ReportMeta): string {
  const model = buildReportModel(findings);
  const out: string[] = [];

  out.push(messages.markdownTitle, '');
  out.push(messages.markdownTargetProject(meta.rootDir), '');

  if (model.total === 0) {
    out.push(messages.markdownNoIssues, '');
    out.push(scanNote(meta));
    return out.join('\n');
  }

  out.push(messages.markdownSummary(model.total, formatSeverityCounts(model.counts)), '');
  out.push(scanNote(meta), '');
  out.push(messages.markdownHeuristicNote, '');

  const ordered = orderedFindings(model);
  for (const severity of SEVERITY_ORDER) {
    const inSeverity = ordered.filter((finding) => finding.severity === severity);
    if (inSeverity.length === 0) {
      continue;
    }
    out.push(`## ${SEVERITY_HEADING[severity]} (${inSeverity.length})`, '');
    for (const finding of inSeverity) {
      out.push(...renderFinding(finding, meta.rootDir));
    }
  }

  return out.join('\n');
}

function renderFinding(finding: Finding, rootDir: string): string[] {
  const heuristic = finding.confidence === 'heuristic' ? ' `[heuristic]`' : '';
  const location = `${relativize(rootDir, finding.file)}:${finding.line}`;
  return [
    `### ${finding.ruleId} — ${finding.target}${heuristic}`,
    '',
    `\`${location}\``,
    '',
    `**${messages.whyDangerousLabel}** ${finding.whyDangerous}`,
    '',
    `**${messages.recommendedFixLabel}**`,
    '',
    // Recommendations mix a prose line with a code example, so a plain fence
    // (no language tag) is more honest than mis-highlighting the prose as JS.
    '```',
    finding.recommendation,
    '```',
    '',
  ];
}

function scanNote(meta: ReportMeta): string {
  const parts = [messages.countScanned(meta.filesScanned)];
  if (meta.filesUnparsable > 0) parts.push(messages.countUnparsable(meta.filesUnparsable));
  if (meta.filesSkippedOversized > 0) parts.push(messages.countOversized(meta.filesSkippedOversized));
  if (meta.filesSkippedOutsideRoot > 0) parts.push(messages.countOutsideRoot(meta.filesSkippedOutsideRoot));
  return `_${parts.join(', ')}._`;
}

function relativize(rootDir: string, file: string): string {
  if (!path.isAbsolute(file)) {
    return file;
  }
  const relative = path.relative(rootDir, file);
  return relative.startsWith('..') ? file : relative;
}
