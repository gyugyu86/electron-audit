import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import type { Rule } from '../../src/core/types.js';
import { EA001 } from '../../src/core/rules/EA001.js';
import { EA002 } from '../../src/core/rules/EA002.js';
import { EA003 } from '../../src/core/rules/EA003.js';
import { EA004 } from '../../src/core/rules/EA004.js';
import { EA005 } from '../../src/core/rules/EA005.js';
import { EA007 } from '../../src/core/rules/EA007.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

function run(rules: Rule[], fixtureRelPath: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureRelPath) });
  return new RuleEngine(rules).run(scan.files, scan.project);
}

const A_GROUP = [EA001, EA002, EA003, EA004, EA005, EA007];

// `new BrowserWindow(getOptions())` where getOptions is a same-file function
// returning an object literal — resolved to that literal so the config is
// graded, not written off as dynamic. The invariant that matters: resolution
// only silences a config it proves SAFE; a dangerous return still fires (high),
// and anything unresolvable stays dynamic (heuristic — still fires). A missed
// critical is the failure mode this must never introduce.
describe('webPreferences from a same-file function return', () => {
  it('resolves a safe helper return: no A-group findings (the fiddle idiom)', () => {
    expect(run(A_GROUP, 'webpref-fn-return/safe-fn').findings).toEqual([]);
  });

  it('resolves a dangerous helper return: EA001 fires at HIGH confidence (not heuristic)', () => {
    const findings = run([EA001], 'webpref-fn-return/dangerous-fn').findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'EA001', severity: 'critical', confidence: 'high' });
  });

  // Each violates exactly one of the resolution conditions; all must stay
  // 'dynamic' → EA001 keeps firing heuristically on the (dangerous) config,
  // never silently dropped.
  it.each([
    ['cross-file', 'the helper is defined in another file'],
    ['multi-return', 'branching with multiple returns'],
    ['arg-dependent', 'the return depends on an argument'],
    ['spread', 'the returned object has an unresolvable spread'],
  ])('keeps %s dynamic → EA001 heuristic (%s)', (fixture) => {
    const findings = run([EA001], `webpref-fn-return/${fixture}`).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'EA001', severity: 'critical', confidence: 'heuristic' });
  });
});
