import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Finding, Rule, Severity } from './types.js';
import { defaultConfig, type AuditConfig, type RuleConfigOverride } from '../config/defaultConfig.js';

const VALID_SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// Thrown for any user-facing config problem (missing file, bad JSON, wrong
// shape). The CLI prints `.message` and exits without a stack trace — a
// broken config is a user error, not a tool crash.
export class ConfigError extends Error {}

// Loads a JSON or JS/MJS/CJS config file describing rule overrides. Every
// failure mode surfaces as a ConfigError with an actionable message rather
// than an unhandled throw.
export async function loadConfig(configPath: string): Promise<AuditConfig> {
  const resolved = path.resolve(configPath);
  if (!existsSync(resolved)) {
    throw new ConfigError(`Config file not found: ${configPath}`);
  }

  const raw = await readConfigFile(resolved);
  return validateConfig(raw, configPath);
}

async function readConfigFile(resolved: string): Promise<unknown> {
  const ext = path.extname(resolved).toLowerCase();
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
    let mod: { default?: unknown };
    try {
      mod = (await import(pathToFileURL(resolved).href)) as { default?: unknown };
    } catch (error) {
      throw new ConfigError(`Failed to load config file (JS): ${(error as Error).message}`);
    }
    return mod.default ?? mod;
  }

  let text: string;
  try {
    text = readFileSync(resolved, 'utf8');
  } catch (error) {
    throw new ConfigError(`Failed to read config file: ${(error as Error).message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new ConfigError(`Invalid JSON in config file: ${(error as Error).message}`);
  }
}

function validateConfig(raw: unknown, configPath: string): AuditConfig {
  if (typeof raw !== 'object' || raw === null) {
    throw new ConfigError(`Config file must be an object: ${configPath}`);
  }
  const overridesRaw = (raw as { ruleOverrides?: unknown }).ruleOverrides ?? {};
  if (typeof overridesRaw !== 'object' || overridesRaw === null) {
    throw new ConfigError('`ruleOverrides` must be an object of the form { ruleId: { enabled?, severity? } }.');
  }

  const ruleOverrides: Record<string, RuleConfigOverride> = {};
  for (const [ruleId, value] of Object.entries(overridesRaw as Record<string, unknown>)) {
    if (typeof value !== 'object' || value === null) {
      throw new ConfigError(`Config for rule "${ruleId}" must be an object.`);
    }
    const { enabled, severity } = value as { enabled?: unknown; severity?: unknown };
    if (enabled !== undefined && typeof enabled !== 'boolean') {
      throw new ConfigError(`"enabled" for rule "${ruleId}" must be true or false.`);
    }
    if (severity !== undefined && !VALID_SEVERITIES.includes(severity as Severity)) {
      throw new ConfigError(
        `"severity" for rule "${ruleId}" must be one of ${VALID_SEVERITIES.join('/')} (got: ${String(severity)}).`,
      );
    }
    ruleOverrides[ruleId] = { enabled: enabled as boolean | undefined, severity: severity as Severity | undefined };
  }

  return { ruleOverrides: { ...defaultConfig.ruleOverrides, ...ruleOverrides } };
}

// Rules left enabled after applying the config (a rule is on unless its
// override sets enabled:false).
export function resolveEnabledRules(rules: Rule[], config: AuditConfig): Rule[] {
  return rules.filter((rule) => config.ruleOverrides[rule.id]?.enabled !== false);
}

// Applies per-rule severity overrides to already-produced findings.
export function applySeverityOverrides(findings: Finding[], config: AuditConfig): Finding[] {
  return findings.map((finding) => {
    const override = config.ruleOverrides[finding.ruleId]?.severity;
    return override ? { ...finding, severity: override } : finding;
  });
}
