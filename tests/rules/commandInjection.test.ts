import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA020 } from '../../src/core/rules/EA020.js';
import { EA021 } from '../../src/core/rules/EA021.js';
import { EA022 } from '../../src/core/rules/EA022.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(dirname, '../fixtures');

function run(fixtureRelPath: string) {
  const scan = scanProject({ rootDir: path.join(FIXTURES_ROOT, fixtureRelPath) });
  return new RuleEngine([EA020, EA021, EA022]).run(scan.files);
}

describe('EA020 command injection (exec/execSync/spawn shell:true)', () => {
  it('flags template-interpolated exec() as critical, high-confidence', () => {
    const result = run('EA020/vulnerable');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA020', severity: 'critical', confidence: 'high' });
  });

  it('flags spawn(cmd, { shell: true }) the same as exec', () => {
    const result = run('EA020/spawn-shell-true');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA020', severity: 'critical', confidence: 'high' });
  });

  it('stays silent for execFile with an argument array', () => {
    expect(run('EA020/safe-execFile').findings).toHaveLength(0);
  });

  it('stays silent for a fully static literal command', () => {
    expect(run('EA020/safe-literal').findings).toHaveLength(0);
  });

  it('stays silent for spawn without shell:true', () => {
    expect(run('EA020/safe-spawn-no-shell').findings).toHaveLength(0);
  });

  it('stays silent for spawn with a dynamic shell option but a fully static literal cmd', () => {
    expect(run('EA020/safe-spawn-shell-dynamic-literal').findings).toHaveLength(0);
  });
});

describe('EA021 command injection + privilege escalation (sudo-prompt)', () => {
  it('escalates a template-interpolated sudo.exec() to EA021 only (no duplicate EA020)', () => {
    const result = run('EA021/vulnerable');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA021', severity: 'critical', confidence: 'high' });
  });

  it('stays silent for sudo.exec() with a static literal command', () => {
    expect(run('EA021/safe-literal').findings).toHaveLength(0);
  });
});

describe('EA022 command injection heuristic (unresolvable variable)', () => {
  it('flags exec(param) as high, heuristic-confidence — not critical', () => {
    const result = run('EA022/heuristic');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA022', severity: 'high', confidence: 'heuristic' });
  });

  it('flags spawn(cmd, { shell: <dynamic> }) with a risky cmd as heuristic, not critical — sink activation itself is uncertain', () => {
    const result = run('EA022/spawn-shell-dynamic');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({ ruleId: 'EA022', severity: 'high', confidence: 'heuristic' });
  });
});
