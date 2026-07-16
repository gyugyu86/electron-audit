import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCommandInjectionSites } from './shared/commandInjection.js';

const WHY_DANGEROUS =
  'Interpolating or concatenating an externally-influenceable value directly into a shell command string lets an ' +
  'attacker inject shell metacharacters (semicolons, backticks, etc.) to run an unintended command alongside the ' +
  'intended one (command injection).';

const RECOMMENDATION = `Pass arguments as an array to execFile (or spawn with shell:false) instead of exec/execSync, so the value never goes through shell parsing.

// vulnerable
const { exec } = require('child_process');
exec(\`kill \${pid}\`);

// fixed — arguments split into an array, no shell involved
const { execFile } = require('child_process');
execFile('kill', [String(pid)]);`;

export const EA020: NodeRule = {
  id: 'EA020',
  kind: 'node',
  severity: 'critical',
  target: 'Interpolated/concatenated command string in child_process exec/execSync (or spawn with shell:true)',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    return findCommandInjectionSites(context.ast, context.file.path, context.file.content)
      .filter((site) => site.ruleId === 'EA020')
      .map((site) => ({ ...site, whyDangerous: WHY_DANGEROUS, recommendation: RECOMMENDATION }));
  },
};
