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
import { messages } from './messages.js';
import { readPackageVersion } from './version.js';

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
  .version(readPackageVersion(), '-v, --version', messages.optVersion)
  .description(messages.cliDescription)
  .argument('<target-path>', messages.argTargetPath)
  .option('--json', messages.optJson)
  .option('--markdown', messages.optMarkdown)
  .option('--sarif', messages.optSarif)
  .option('--config <path>', messages.optConfig)
  .option('--strict', messages.optStrict)
  .option('--no-fail', messages.optNoFail)
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
      console.error(chalk.red(messages.configErrorPrefix(error.message)));
      process.exit(2);
    }
    throw error;
  }
}

function printTerminalSkipNotes(filesScanned: number, meta: ReportMeta): void {
  const notes: string[] = [];
  if (meta.filesUnparsable > 0) notes.push(messages.countUnparsable(meta.filesUnparsable));
  if (meta.filesSkippedOversized > 0) notes.push(messages.countOversized(meta.filesSkippedOversized));
  if (meta.filesSkippedOutsideRoot > 0) notes.push(messages.countOutsideRoot(meta.filesSkippedOutsideRoot));
  if (notes.length > 0) {
    console.error(chalk.dim(messages.terminalSkipNote(notes.join(', '), filesScanned)));
  }
}
