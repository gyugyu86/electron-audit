import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Finding } from '../../src/core/types.js';
import type { NodeRule } from '../../src/core/types.js';
import { applySeverityOverrides, ConfigError, loadConfig, resolveEnabledRules } from '../../src/core/config.js';

let scratch: string | undefined;

function scratchDir(): string {
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ea-config-'));
  return scratch;
}

afterEach(() => {
  if (scratch) {
    fs.rmSync(scratch, { recursive: true, force: true });
    scratch = undefined;
  }
});

function stubRule(id: string): NodeRule {
  return { id, kind: 'node', severity: 'high', target: '', whyDangerous: '', recommendation: '', check: () => [] };
}

function stubFinding(ruleId: string): Finding {
  return { ruleId, severity: 'critical', confidence: 'high', file: 'f', line: 1, target: '', whyDangerous: '', recommendation: '' };
}

describe('loadConfig', () => {
  it('loads a valid JSON config', async () => {
    const dir = scratchDir();
    const file = path.join(dir, 'c.json');
    fs.writeFileSync(file, JSON.stringify({ ruleOverrides: { EA001: { enabled: false }, EA002: { severity: 'low' } } }));
    const config = await loadConfig(file);
    expect(config.ruleOverrides.EA001?.enabled).toBe(false);
    expect(config.ruleOverrides.EA002?.severity).toBe('low');
  });

  it('loads a JS (.mjs) config via default export', async () => {
    const dir = scratchDir();
    const file = path.join(dir, 'c.mjs');
    fs.writeFileSync(file, 'export default { ruleOverrides: { EA001: { enabled: false } } };');
    const config = await loadConfig(file);
    expect(config.ruleOverrides.EA001?.enabled).toBe(false);
  });

  it('rejects a missing file with a ConfigError', async () => {
    await expect(loadConfig('/no/such/config.json')).rejects.toBeInstanceOf(ConfigError);
  });

  it('rejects malformed JSON with a ConfigError', async () => {
    const dir = scratchDir();
    const file = path.join(dir, 'bad.json');
    fs.writeFileSync(file, '{ not valid json');
    await expect(loadConfig(file)).rejects.toBeInstanceOf(ConfigError);
  });

  it('rejects an invalid severity value with a ConfigError', async () => {
    const dir = scratchDir();
    const file = path.join(dir, 'bad.json');
    fs.writeFileSync(file, JSON.stringify({ ruleOverrides: { EA001: { severity: 'extreme' } } }));
    await expect(loadConfig(file)).rejects.toBeInstanceOf(ConfigError);
  });
});

describe('resolveEnabledRules / applySeverityOverrides', () => {
  it('filters out rules disabled by config', () => {
    const rules = [stubRule('EA001'), stubRule('EA002')];
    const enabled = resolveEnabledRules(rules, { ruleOverrides: { EA001: { enabled: false } } });
    expect(enabled.map((r) => r.id)).toEqual(['EA002']);
  });

  it('remaps severity on findings whose rule is overridden', () => {
    const result = applySeverityOverrides([stubFinding('EA001'), stubFinding('EA002')], {
      ruleOverrides: { EA001: { severity: 'low' } },
    });
    expect(result.find((f) => f.ruleId === 'EA001')?.severity).toBe('low');
    expect(result.find((f) => f.ruleId === 'EA002')?.severity).toBe('critical');
  });
});
