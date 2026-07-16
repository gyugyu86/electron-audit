import chalk from 'chalk';
import type { Finding, Severity } from '../../core/types.js';
import { buildReportModel, formatSeverityCounts } from './reportModel.js';

const SEVERITY_BADGE: Record<Severity, (text: string) => string> = {
  critical: (text) => chalk.bgRed.white.bold(text),
  high: (text) => chalk.red.bold(text),
  medium: (text) => chalk.yellow.bold(text),
  low: (text) => chalk.cyan.bold(text),
  info: (text) => chalk.gray.bold(text),
};

// Groups findings by location (a site like main.js:16 with four findings is
// shown once, rules listed under it), orders critical→info, and ends with a
// per-severity summary. `confidence: 'heuristic'` stays visually distinct via
// a [heuristic] tag — M3's "no false positives" bar depends on a reader being
// able to tell certain findings from heuristic ones at a glance.
export function formatTerminalReport(findings: Finding[]): string {
  if (findings.length === 0) {
    return chalk.green('탐지된 취약점이 없습니다.');
  }

  const model = buildReportModel(findings);
  const lines: string[] = [];

  for (const group of model.groups) {
    lines.push(chalk.underline(`${group.file}:${group.line}`));
    for (const finding of group.findings) {
      lines.push(...renderFinding(finding));
    }
    lines.push('');
  }

  lines.push(chalk.bold(`총 ${model.total}건 발견 (${formatSeverityCounts(model.counts)})`));
  return lines.join('\n');
}

function renderFinding(finding: Finding): string[] {
  const badge = SEVERITY_BADGE[finding.severity](` ${finding.severity.toUpperCase()} `);
  const confidenceTag = finding.confidence === 'heuristic' ? chalk.yellow(' [heuristic]') : '';
  const lines = [
    `  ${badge}${confidenceTag} ${chalk.bold(finding.ruleId)}  ${finding.target}`,
    `    ${chalk.dim('왜 위험한가:')} ${finding.whyDangerous}`,
    `    ${chalk.dim('권장 수정:')}`,
  ];
  for (const recommendationLine of finding.recommendation.split('\n')) {
    lines.push(`      ${recommendationLine}`);
  }
  return lines;
}
