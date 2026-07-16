import { describe, expect, it } from 'vitest';
import type { Finding, Severity, Confidence } from '../../src/core/types.js';
import { computeExitCode } from '../../src/cli/exitCode.js';

function finding(severity: Severity, confidence: Confidence): Finding {
  return { ruleId: 'EAxxx', severity, confidence, file: 'f', line: 1, target: '', whyDangerous: '', recommendation: '' };
}

describe('computeExitCode', () => {
  it('default: fails on a high-confidence critical/high finding', () => {
    expect(computeExitCode([finding('critical', 'high')], 'default')).toBe(1);
    expect(computeExitCode([finding('high', 'high')], 'default')).toBe(1);
  });

  it('default: does NOT fail on heuristic findings (even at high severity)', () => {
    expect(computeExitCode([finding('critical', 'heuristic')], 'default')).toBe(0);
    expect(computeExitCode([finding('high', 'heuristic')], 'default')).toBe(0);
  });

  it('default: does NOT fail on medium/low/info even at high confidence', () => {
    expect(computeExitCode([finding('medium', 'high')], 'default')).toBe(0);
    expect(computeExitCode([finding('low', 'high')], 'default')).toBe(0);
    expect(computeExitCode([finding('info', 'high')], 'default')).toBe(0);
  });

  it('strict: also fails on a heuristic critical/high finding', () => {
    expect(computeExitCode([finding('high', 'heuristic')], 'strict')).toBe(1);
    // still bounded by severity — a heuristic medium does not fail
    expect(computeExitCode([finding('medium', 'heuristic')], 'strict')).toBe(0);
  });

  it('none: always exits 0', () => {
    expect(computeExitCode([finding('critical', 'high')], 'none')).toBe(0);
  });

  it('exits 0 for no findings in every mode', () => {
    expect(computeExitCode([], 'default')).toBe(0);
    expect(computeExitCode([], 'strict')).toBe(0);
    expect(computeExitCode([], 'none')).toBe(0);
  });
});
