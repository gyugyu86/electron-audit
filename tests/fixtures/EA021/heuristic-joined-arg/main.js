const sudoPrompt = require('@vscode/sudo-prompt');

// Command parts joined at the call site. Same reasoning as the variable form:
// not statically provable (heuristic), still privilege escalation (critical).
function enableLoopback(appId) {
  const parts = ['CheckNetIsolation.exe', 'LoopbackExempt', '-a', `-n=${appId}`];
  sudoPrompt.exec(parts.join(' '), { name: 'MyApp' }, () => {});
}

module.exports = { enableLoopback };
