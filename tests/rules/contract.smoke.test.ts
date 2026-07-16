import { describe, expect, it } from 'vitest';
import type { AggregateRule, Finding, NodeRule, Rule } from '../../src/core/types.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { classifyFileRole } from '../../src/core/fileRoleClassifier.js';
import { extractWebPreferences } from '../../src/core/ast/webPreferencesExtractor.js';
import { isStaticSafeLiteral } from '../../src/core/ast/isStaticSafeLiteral.js';
import { tokenizeCsp } from '../../src/core/csp/cspTokenizer.js';

// Not a behavior test — the engine contract has no logic yet (M1 fills it
// in). This only confirms the six stubs compile and export the shapes the
// contract promises, so `npm test` fails loudly if a signature drifts.
describe('engine contract stubs', () => {
  it('types.ts: Finding/NodeRule/AggregateRule shapes compile with English field names', () => {
    const finding: Finding = {
      ruleId: 'EA001',
      severity: 'critical',
      confidence: 'high',
      file: 'src/main.js',
      line: 12,
      target: 'nodeIntegration: true',
      whyDangerous: '렌더러에 Node API가 노출됩니다.',
      recommendation: 'nodeIntegration: false + preload/contextBridge 사용',
    };
    const nodeRule: NodeRule = {
      id: 'EA001',
      kind: 'node',
      severity: 'critical',
      target: 'BrowserWindow webPreferences',
      whyDangerous: '...',
      recommendation: '...',
      check: () => [],
    };
    const aggregateRule: AggregateRule = {
      id: 'EA010',
      kind: 'aggregate',
      severity: 'high',
      target: 'CSP absence',
      whyDangerous: '...',
      recommendation: '...',
      check: () => [],
    };
    const rules: Rule[] = [nodeRule, aggregateRule];

    expect(finding.ruleId).toBe('EA001');
    expect(finding.confidence).toBe('high');
    expect(rules.map((r) => r.kind)).toEqual(['node', 'aggregate']);
  });

  it('ruleEngine.ts: RuleEngine is constructible and exposes run()', () => {
    const engine = new RuleEngine([]);
    expect(typeof engine.run).toBe('function');
  });

  it('fileRoleClassifier.ts: classifyFileRole is exported', () => {
    expect(typeof classifyFileRole).toBe('function');
  });

  it('ast/webPreferencesExtractor.ts: extractWebPreferences is exported', () => {
    expect(typeof extractWebPreferences).toBe('function');
  });

  it('ast/isStaticSafeLiteral.ts: isStaticSafeLiteral is exported', () => {
    expect(typeof isStaticSafeLiteral).toBe('function');
  });

  it('csp/cspTokenizer.ts: tokenizeCsp is exported', () => {
    expect(typeof tokenizeCsp).toBe('function');
  });
});
