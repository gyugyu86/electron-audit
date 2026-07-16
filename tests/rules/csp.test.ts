import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import type { Rule } from '../../src/core/types.js';
import { EA010 } from '../../src/core/rules/EA010.js';
import { EA011 } from '../../src/core/rules/EA011.js';
import { EA012 } from '../../src/core/rules/EA012.js';
import { EA013 } from '../../src/core/rules/EA013.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

function run(rules: Rule[], fixtureRelPath: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureRelPath) });
  return new RuleEngine(rules).run(scan.files, scan.project);
}

describe('EA010 CSP absence (heuristic, JS-scope-limited)', () => {
  it('stays silent when CSP is set in JS', () => {
    expect(run([EA010], 'EA010/has-csp').findings).toHaveLength(0);
  });

  it('fires heuristic when a window exists but no CSP is found in JS', () => {
    const result = run([EA010], 'EA010/absent');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA010', severity: 'high', confidence: 'heuristic' });
  });

  it('stays silent when there is no BrowserWindow (no renderer to protect)', () => {
    expect(run([EA010], 'EA010/no-window').findings).toHaveLength(0);
  });
});

describe('EA011 unsafe-inline / unsafe-eval', () => {
  it('flags unsafe-inline as high, high-confidence', () => {
    expect(run([EA011], 'EA011/unsafe-inline').findings[0]).toMatchObject({
      ruleId: 'EA011',
      severity: 'high',
      confidence: 'high',
    });
  });

  it('flags unsafe-eval', () => {
    expect(run([EA011], 'EA011/unsafe-eval').findings[0]).toMatchObject({ ruleId: 'EA011', severity: 'high' });
  });

  it('stays silent for a CSP with neither', () => {
    expect(run([EA011], 'EA011/safe').findings).toHaveLength(0);
  });
});

// The core EA012 regression anchor: only a bare `*` token fires.
describe('EA012 wildcard (exact-token only)', () => {
  it('flags a bare `*` source', () => {
    const result = run([EA012], 'EA012/bare-wildcard');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA012', severity: 'medium', confidence: 'high' });
  });

  it('stays silent for a subdomain wildcard `*.foo.com`', () => {
    expect(run([EA012], 'EA012/subdomain-wildcard').findings).toHaveLength(0);
  });

  it('stays silent for a scheme+subdomain wildcard `https://*.cdn.com`', () => {
    expect(run([EA012], 'EA012/scheme-subdomain-wildcard').findings).toHaveLength(0);
  });
});

describe('EA013 Cordova leftover (gap:)', () => {
  it('flags a gap: source as info', () => {
    expect(run([EA013], 'EA013/cordova-gap').findings[0]).toMatchObject({ ruleId: 'EA013', severity: 'info' });
  });

  it('stays silent for a CSP with no Cordova signature', () => {
    expect(run([EA013], 'EA013/no-gap').findings).toHaveLength(0);
  });
});
