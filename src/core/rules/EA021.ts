import type { Finding, NodeRule, NodeRuleContext } from '../types.js';
import { findCommandInjectionSites } from './shared/commandInjection.js';

const WHY_DANGEROUS =
  'When a command-injection vulnerability is combined with a sudo-prompt-style privilege-escalation wrapper, the ' +
  'injected command runs with full administrator privileges once the user approves the prompt. If a value ' +
  'originating from the renderer or the network reaches this point, the entire system is compromised.';

const RECOMMENDATION = `Run only a fixed whitelist of commands where privilege escalation is needed, and pass arguments only after validating them.
sudo-prompt-style wrappers go through a shell internally, so never interpolate external input into the command string.

// vulnerable
sudo.exec(\`some-tool --target=\${url}\`, options, callback);

// fixed — a fixed whitelisted command + validated arguments only
const ALLOWED_TARGETS = new Set(['a', 'b']);
if (!ALLOWED_TARGETS.has(target)) throw new Error('invalid target');
sudo.exec(\`some-tool --target=\${target}\`, options, callback);`;

export const EA021: NodeRule = {
  id: 'EA021',
  kind: 'node',
  severity: 'critical',
  target: 'Interpolated/concatenated command string in a sudo-prompt-style privilege-escalation exec',
  whyDangerous: WHY_DANGEROUS,
  recommendation: RECOMMENDATION,
  check(context: NodeRuleContext): Finding[] {
    return findCommandInjectionSites(context.ast, context.file.path, context.file.content)
      .filter((site) => site.ruleId === 'EA021')
      .map((site) => ({ ...site, whyDangerous: WHY_DANGEROUS, recommendation: RECOMMENDATION }));
  },
};
