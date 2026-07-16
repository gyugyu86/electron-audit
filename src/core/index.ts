// Public entry point for the reusable analysis engine. The architecture
// keeps `core` independent of the CLI so a GUI or GitHub Action can drive it
// directly — this barrel is that programmatic surface.
export { scanProject } from './scanner.js';
export type { ScanOptions, ScanResult } from './scanner.js';
export { RuleEngine } from './ruleEngine.js';
export type { RuleEngineRunResult } from './ruleEngine.js';
export { ALL_RULES } from './rules/index.js';
export { buildReport } from './report.js';
export type { Report } from './report.js';
export type {
  Finding,
  Rule,
  NodeRule,
  AggregateRule,
  NodeRuleContext,
  AggregateRuleContext,
  Severity,
  Confidence,
  FileRole,
  ProjectContext,
  ScannedFile,
  ParsedProjectFile,
} from './types.js';
