import type { File } from '@babel/types';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Confidence = 'high' | 'heuristic';

export type FileRole = 'main' | 'preload' | 'renderer';

export interface Finding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  file: string;
  line: number;
  target: string;
  whyDangerous: string;
  recommendation: string;
}

export interface ScannedFile {
  path: string;
  content: string;
  role: FileRole;
}

// Project-wide facts a rule may need beyond a single file. Populated once by
// the scanner from the target project's package.json.
export interface ProjectContext {
  // Major version of the `electron` dependency, or undefined if it couldn't
  // be read/parsed. Used by EA002/EA003 to decide whether an *absent*
  // webPreferences key is dangerous (some secure defaults are version-gated),
  // and by EA062 to judge version staleness.
  electronMajorVersion?: number;
  // The scanned project's root directory. EA061 reads config files (e.g.
  // electron-builder.json) relative to it.
  rootDir?: string;
  // Absolute path to the project's package.json, if one exists — the anchor
  // for aggregate findings that are about the manifest itself (EA060/EA061/
  // EA062), which isn't one of the scanned .js/.ts source files.
  packageJsonPath?: string;
  // Names of every dependency + devDependency. Used by EA060 (telemetry SDK
  // presence) and EA061 (is electron-builder used at all?).
  dependencyNames?: Set<string>;
  // The package.json `build` field verbatim, if present (electron-builder's
  // inline config). EA061 inspects it for signing settings.
  packageJsonBuild?: unknown;
  // CSP strings extracted from HTML <meta http-equiv> tags. HTML isn't JS-
  // parsed, so its CSP is gathered here at scan time and fed to EA010/011/012
  // alongside JS-sourced CSP — same tokenizer/judgment, broader source.
  htmlCspSites?: HtmlCspSite[];
}

export interface HtmlCspSite {
  file: string;
  line: number;
  value: string;
}

export interface ParsedProjectFile {
  file: ScannedFile;
  ast: File;
}

export interface NodeRuleContext {
  file: ScannedFile;
  ast: File;
  project: ProjectContext;
}

export interface AggregateRuleContext {
  files: ScannedFile[];
  // The same files already parsed once by the engine — aggregate rules that
  // need ASTs project-wide (EA006 cross-window, EA041 handler absence) read
  // these instead of re-parsing. Unparsable files are excluded.
  parsedFiles: ParsedProjectFile[];
  project: ProjectContext;
}

interface BaseRule {
  id: string;
  severity: Severity;
  target: string;
  whyDangerous: string;
  recommendation: string;
}

export interface NodeRule extends BaseRule {
  kind: 'node';
  check(context: NodeRuleContext): Finding[];
}

export interface AggregateRule extends BaseRule {
  kind: 'aggregate';
  check(context: AggregateRuleContext): Finding[];
}

export type Rule = NodeRule | AggregateRule;
