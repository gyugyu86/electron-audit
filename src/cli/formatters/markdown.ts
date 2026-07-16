import path from 'node:path';
import type { Finding, Severity } from '../../core/types.js';
import { buildReportModel, formatSeverityCounts, orderedFindings, SEVERITY_ORDER, type ReportMeta } from './reportModel.js';

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

  out.push('# electron-audit 리포트', '');
  out.push(`**대상 프로젝트:** \`${meta.rootDir}\``, '');

  if (model.total === 0) {
    out.push('✅ 탐지된 문제가 없습니다.', '');
    out.push(scanNote(meta));
    return out.join('\n');
  }

  out.push(`**요약:** 총 ${model.total}건 — ${formatSeverityCounts(model.counts)}`, '');
  out.push(scanNote(meta), '');
  out.push(
    '> `[heuristic]` 표시는 정적 분석만으로 확정할 수 없어 오탐 가능성이 있는 탐지입니다. 표시가 없으면 high-confidence(확실) 탐지입니다.',
    '',
  );

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
    `**왜 위험한가:** ${finding.whyDangerous}`,
    '',
    '**권장 수정:**',
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
  const parts = [`스캔한 파일 ${meta.filesScanned}개`];
  if (meta.filesUnparsable > 0) parts.push(`파싱 실패 ${meta.filesUnparsable}개`);
  if (meta.filesSkippedOversized > 0) parts.push(`용량 초과 제외 ${meta.filesSkippedOversized}개`);
  if (meta.filesSkippedOutsideRoot > 0) parts.push(`루트 밖 심볼릭 링크 제외 ${meta.filesSkippedOutsideRoot}개`);
  return `_${parts.join(', ')}._`;
}

function relativize(rootDir: string, file: string): string {
  if (!path.isAbsolute(file)) {
    return file;
  }
  const relative = path.relative(rootDir, file);
  return relative.startsWith('..') ? file : relative;
}
