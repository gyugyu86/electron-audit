import type { Severity } from '../core/types.js';

export interface RuleConfigOverride {
  enabled?: boolean;
  severity?: Severity;
}

export interface AuditConfig {
  ruleOverrides: Record<string, RuleConfigOverride>;
}

// No overrides by default — every rule in ALL_RULES runs at its declared
// severity. A user's --config file is merged over this.
export const defaultConfig: AuditConfig = {
  ruleOverrides: {},
};
