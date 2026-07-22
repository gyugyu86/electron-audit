// Central store for the CLI's user-facing strings: the terminal and markdown
// formatter labels plus the commander usage/help text. Kept as one flat,
// key-based object so a locale sibling (e.g. a `ko` object) can be added later
// and selected by a --lang flag; today only English exists, and no switching
// framework is built. Static messages are plain strings; parameterized ones
// are small functions.
//
// This module holds CLI-layer strings only. `core` owns its own messages (see
// core/config.ts) so it stays independent of the CLI and remains reusable from
// a GUI or GitHub Action — do not import this module from core.
export const messages = {
  // --- commander usage / help (cli/index.ts) ---
  cliDescription: 'Statically analyze a local Electron project for known security anti-patterns.',
  argTargetPath: 'Path to the Electron project to analyze',
  optJson: 'Output JSON (for CI / downstream tools)',
  optMarkdown: 'Output a Markdown report',
  optSarif: 'Output SARIF 2.1.0 (for GitHub code scanning)',
  optConfig: 'Config file for rule on/off and severity overrides (JSON or JS)',
  optStrict: 'Count heuristic findings toward the exit code too (exit 1 when severity ≥ high)',
  optNoFail: 'Always exit 0 even when there are findings (report only)',
  optVersion: "Output the tool's version and exit",
  configErrorPrefix: (message: string): string => `Config error: ${message}`,

  // --- scan notes (shared by the terminal skip-note line and markdown scan-note) ---
  countScanned: (n: number): string => `${n} files scanned`,
  countUnparsable: (n: number): string => `${n} failed to parse`,
  countOversized: (n: number): string => `${n} skipped (over size limit)`,
  countOutsideRoot: (n: number): string => `${n} symlink(s) outside root skipped`,
  terminalSkipNote: (notes: string, filesScanned: number): string => `(${notes} / ${filesScanned} files scanned)`,

  // --- finding labels (shared by both formatters; each applies its own styling) ---
  whyDangerousLabel: "Why it's dangerous:",
  recommendedFixLabel: 'Recommended fix:',

  // --- terminal report (cli/formatters/terminal.ts) ---
  terminalNoFindings: 'No vulnerabilities found.',
  terminalSummary: (total: number, counts: string): string =>
    `${total} finding${total === 1 ? '' : 's'} (${counts})`,

  // --- markdown report (cli/formatters/markdown.ts) ---
  markdownTitle: '# electron-audit report',
  markdownTargetProject: (rootDir: string): string => `**Target project:** \`${rootDir}\``,
  markdownNoIssues: '✅ No issues found.',
  markdownSummary: (total: number, counts: string): string =>
    `**Summary:** ${total} finding${total === 1 ? '' : 's'} — ${counts}`,
  markdownHeuristicNote:
    '> `[heuristic]` marks findings that static analysis alone cannot confirm, so they may be false positives. Findings without the tag are high-confidence.',
} as const;
