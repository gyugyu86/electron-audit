const sudo = require('sudo-prompt');

// The command is assembled first and handed over as a plain variable — the
// shape real apps use. The argument isn't a statically provable literal, so
// the finding is heuristic, but it is still a root shell: EA021 critical.
function elevateAndRun(target) {
  const cmd = 'some-tool --target=' + target;
  sudo.exec(cmd, { name: 'MyApp' }, () => {});
}

module.exports = { elevateAndRun };
