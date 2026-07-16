import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCommandInjectionSites } from './shared/commandInjection.js';

const WHY_DANGEROUS =
  "The value passed to a shell command is a variable that can't be statically proven safe. If it originates from " +
  "user input, a network response, or another external source, it could lead to command injection. Static " +
  "analysis alone can't confirm whether it's tainted, so this is reported as a heuristic — check the value's " +
  "origin directly to determine whether it's actually exploitable.";

const RECOMMENDATION = `Validate this variable before it reaches the shell, or switch to execFile + an argument array to avoid shell parsing entirely.

// passed through with no validation
exec(command);

// fixed — passed as an argument array, no string assembly, no shell involved
const { execFile } = require('child_process');
execFile(command, args, callback);`;

export const EA022: NodeRule = {
  id: 'EA022',
  kind: 'node',
  severity: 'high',
  target: "A variable passed to a child_process exec-family call that can't be statically proven safe",
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    return findCommandInjectionSites(context.ast, context.file.path, context.file.content)
      .filter((site) => site.ruleId === 'EA022')
      .map((site) => ({ ...site, whyDangerous: WHY_DANGEROUS, recommendation: RECOMMENDATION }));
  },
};
