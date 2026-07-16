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

export interface RuleEngineRunResult {
  findings: Finding[];
  filesScanned: number;
  filesUnparsable: number;
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
    let filesUnparsable = 0;

    for (const file of files) {
      const parsed = parseSource(file.content, file.path);
      if (!parsed) {
        filesUnparsable += 1;
        continue;
      }
      parsedFiles.push({ file, ast: parsed.ast });

      const context: NodeRuleContext = { file, ast: parsed.ast, project };
      for (const rule of nodeRules) {
        findings.push(...rule.check(context));
      }
    }

    if (aggregateRules.length > 0) {
      const aggregateContext: AggregateRuleContext = { files, parsedFiles, project };
      for (const rule of aggregateRules) {
        findings.push(...rule.check(aggregateContext));
      }
    }

    return { findings, filesScanned: files.length, filesUnparsable };
  }
}
