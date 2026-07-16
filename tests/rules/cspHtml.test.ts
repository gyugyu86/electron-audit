import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA010 } from '../../src/core/rules/EA010.js';
import { EA011 } from '../../src/core/rules/EA011.js';
import { EA012 } from '../../src/core/rules/EA012.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures/csp-html');

function run(fixtureName: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES, fixtureName) });
  return new RuleEngine([EA010, EA011, EA012]).run(scan.files, scan.project);
}

describe('CSP in HTML <meta> (source widened from JS to HTML)', () => {
  it('flags the vulnerable <meta> CSP, graded by directive', () => {
    const findings = run('vulnerable').findings;
    const ea011 = findings.filter((f) => f.ruleId === 'EA011');
    const ea012 = findings.filter((f) => f.ruleId === 'EA012');

    // script-src unsafe-inline + unsafe-eval -> HIGH; style-src unsafe-inline -> MEDIUM.
    expect(ea011.some((f) => f.severity === 'high' && f.target.includes('script-src'))).toBe(true);
    expect(ea011.some((f) => f.severity === 'medium' && f.target.includes('style-src'))).toBe(true);
    // every EA011 finding is high-confidence and anchored in the HTML file
    expect(ea011.every((f) => f.confidence === 'high' && f.file.endsWith('index.html'))).toBe(true);
    // wildcard * on default-src -> EA012
    expect(ea012.some((f) => f.target.includes('default-src'))).toBe(true);
  });

  it('does not fire EA010 when a <meta> CSP is present (absence check is now HTML-aware)', () => {
    expect(run('vulnerable').findings.some((f) => f.ruleId === 'EA010')).toBe(false);
    expect(run('safe').findings.some((f) => f.ruleId === 'EA010')).toBe(false);
  });

  it('stays silent on a safe <meta> CSP (no unsafe-inline/eval, no wildcard)', () => {
    const findings = run('safe').findings;
    expect(findings.filter((f) => f.ruleId === 'EA011' || f.ruleId === 'EA012')).toHaveLength(0);
  });
});
