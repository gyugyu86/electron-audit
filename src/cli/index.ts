#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { scanProject } from '../core/scanner.js';
import { RuleEngine } from '../core/ruleEngine.js';
import { ALL_RULES } from '../core/rules/index.js';
import { applySeverityOverrides, ConfigError, loadConfig, resolveEnabledRules } from '../core/config.js';
import { defaultConfig } from '../config/defaultConfig.js';
import { formatTerminalReport } from './formatters/terminal.js';
import { formatJsonReport } from './formatters/json.js';
import { formatMarkdownReport } from './formatters/markdown.js';
import { formatSarifReport } from './formatters/sarif.js';
import type { ReportMeta } from './formatters/reportModel.js';
import { computeExitCode, type FailMode } from './exitCode.js';

interface CliOptions {
  json?: boolean;
  markdown?: boolean;
  sarif?: boolean;
  config?: string;
  strict?: boolean;
  // commander maps --no-fail to `fail: false` (default true).
  fail?: boolean;
}

const program = new Command();

program
  .name('electron-audit')
  .description('로컬 Electron 프로젝트를 정적 분석해 알려진 보안 안티패턴을 탐지합니다.')
  .argument('<target-path>', '분석할 Electron 프로젝트 경로')
  .option('--json', 'JSON으로 출력 (CI/후속 도구용)')
  .option('--markdown', 'Markdown 리포트로 출력')
  .option('--sarif', 'SARIF 2.1.0으로 출력 (GitHub 코드 스캐닝용)')
  .option('--config <path>', '규칙 on/off·심각도 오버라이드 설정 파일 (JSON 또는 JS)')
  .option('--strict', 'heuristic 탐지도 종료코드에 반영 (severity≥high면 exit 1)')
  .option('--no-fail', '탐지가 있어도 항상 exit 0 (리포트 전용)')
  .action(runAudit);

await program.parseAsync();

async function runAudit(targetPath: string, options: CliOptions): Promise<void> {
  const config = options.config ? await loadConfigOrExit(options.config) : defaultConfig;

  const scan = scanProject({ rootDir: targetPath });
  const rules = resolveEnabledRules(ALL_RULES, config);
  const result = new RuleEngine(rules).run(scan.files, scan.project);
  const findings = applySeverityOverrides(result.findings, config);

  const meta: ReportMeta = {
    rootDir: scan.project.rootDir ?? targetPath,
    filesScanned: result.filesScanned,
    filesUnparsable: result.filesUnparsable,
    filesSkippedOversized: scan.skippedOversized,
    filesSkippedOutsideRoot: scan.skippedOutsideRoot,
  };

  if (options.sarif) {
    console.log(formatSarifReport(findings, meta, ALL_RULES));
  } else if (options.json) {
    console.log(formatJsonReport(findings, meta));
  } else if (options.markdown) {
    console.log(formatMarkdownReport(findings, meta));
  } else {
    console.log(formatTerminalReport(findings));
    printTerminalSkipNotes(result.filesScanned, meta);
  }

  // process.exitCode (not process.exit) so buffered stdout flushes fully
  // before the process ends with the chosen code.
  const mode: FailMode = options.fail === false ? 'none' : options.strict ? 'strict' : 'default';
  process.exitCode = computeExitCode(findings, mode);
}

async function loadConfigOrExit(configPath: string): ReturnType<typeof loadConfig> {
  try {
    return await loadConfig(configPath);
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(chalk.red(`설정 오류: ${error.message}`));
      process.exit(2);
    }
    throw error;
  }
}

function printTerminalSkipNotes(filesScanned: number, meta: ReportMeta): void {
  const notes: string[] = [];
  if (meta.filesUnparsable > 0) notes.push(`파싱 실패 ${meta.filesUnparsable}개`);
  if (meta.filesSkippedOversized > 0) notes.push(`용량 초과로 제외 ${meta.filesSkippedOversized}개`);
  if (meta.filesSkippedOutsideRoot > 0) notes.push(`대상 폴더 밖을 가리키는 심볼릭 링크 제외 ${meta.filesSkippedOutsideRoot}개`);
  if (notes.length > 0) {
    console.error(chalk.dim(`(${notes.join(', ')} / 스캔된 파일 ${filesScanned}개)`));
  }
}
