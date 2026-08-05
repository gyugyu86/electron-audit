import type {
  AggregateRule,
  AggregateRuleContext,
  Finding,
  NodeRule,
  NodeRuleContext,
  ParsedProjectFile,
  ProjectContext,
  Rule,
  ScannedFile,
} from './types.js';
import { parseSource } from './parser.js';

export interface AnalysisError {
  file: string;
  message: string;
}

export interface RuleEngineRunResult {
  findings: Finding[];
  filesScanned: number;
  // Files whose SOURCE could not be parsed (parseSource returned undefined).
  filesUnparsable: number;
  // Files that parsed but threw while a rule analyzed them (e.g. babel's
  // scope-crawl on the first traverse throwing `Duplicate declaration`).
  // Counted separately from filesUnparsable because the cause is different:
  // the file is valid enough to parse but not to analyze. These files are
  // skipped, not crashed on. `analysisErrors` carries the per-file messages
  // for debug surfaces; the count is what the report shows by default.
  filesAnalysisErrors: number;
  analysisErrors: AnalysisError[];
}

export class RuleEngine {
  constructor(private readonly rules: Rule[]) {}

  // Dispatches on `rule.kind`: NodeRule runs once per ScannedFile against
  // that file's own parsed AST; AggregateRule runs once against the full
  // parsed file set (used for project-wide checks — "nowhere in the
  // project" absence, EA041, and cross-window comparison, EA006). Each file
  // is parsed exactly once here and the AST is reused for both paths.
  // Results from both are concatenated.
  run(files: ScannedFile[], project: ProjectContext = {}): RuleEngineRunResult {
    const nodeRules = this.rules.filter((rule): rule is NodeRule => rule.kind === 'node');
    const aggregateRules = this.rules.filter((rule): rule is AggregateRule => rule.kind === 'aggregate');

    const findings: Finding[] = [];
    const parsedFiles: ParsedProjectFile[] = [];
    const analysisErrors: AnalysisError[] = [];
    let filesUnparsable = 0;

    for (const file of files) {
      const parsed = parseSource(file.content, file.path);
      if (!parsed) {
        filesUnparsable += 1;
        continue;
      }

      // Isolate analysis PER FILE, not per rule. babel crawls an AST's scope
      // lazily on its first traverse(), so a scope error (e.g. a duplicate
      // binding) throws from whichever node rule traverses first — catching
      // per rule would just re-hit it for all N rules on the same file. Buffer
      // this file's findings so a mid-analysis throw discards the file cleanly:
      // it contributes no findings and, crucially, is NOT added to parsedFiles,
      // so the aggregate pass (which only ever traverses parsedFiles) can't
      // re-encounter and re-throw on it either. The threat model is untrusted
      // third-party code; one unanalyzable file must never kill the whole scan.
      const fileFindings: Finding[] = [];
      try {
        const context: NodeRuleContext = { file, ast: parsed.ast, project };
        for (const rule of nodeRules) {
          fileFindings.push(...rule.check(context));
        }
      } catch (error) {
        analysisErrors.push({ file: file.path, message: (error as Error).message });
        continue;
      }

      findings.push(...fileFindings);
      parsedFiles.push({ file, ast: parsed.ast });
    }

    if (aggregateRules.length > 0) {
      const aggregateContext: AggregateRuleContext = { files, parsedFiles, project };
      for (const rule of aggregateRules) {
        findings.push(...rule.check(aggregateContext));
      }
    }

    return {
      findings: attachRoles(findings, files),
      filesScanned: files.length,
      filesUnparsable,
      filesAnalysisErrors: analysisErrors.length,
      analysisErrors,
    };
  }
}

// Stamps each finding with the role of the file it points at, in ONE place
// after both passes, rather than making every rule carry the role through.
// A rule's job is to decide whether something is dangerous; which kind of file
// it happened to be in is a fact about the scan, and the engine is where
// findings and scanned files meet.
//
// The lookup is by path and may legitimately miss: aggregate rules anchor
// findings on files that were never ScannedFiles — `.html` (collected only for
// its <meta> CSP) and package.json (the manifest behind EA060/EA061/EA062).
// Those keep no role rather than being given a guessed one.
//
// Descriptive only. Nothing downstream branches on it: severity, confidence,
// and the exit-code computation are untouched, so this cannot change whether a
// finding is reported or whether a build passes.
function attachRoles(findings: Finding[], files: ScannedFile[]): Finding[] {
  const roleByPath = new Map(files.map((file) => [file.path, file.role]));
  return findings.map((finding) => {
    const role = roleByPath.get(finding.file);
    return role === undefined ? finding : { ...finding, role };
  });
}
