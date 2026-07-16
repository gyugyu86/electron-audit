const { exec } = require('child_process');

// The untrusted value is used only as a whitelist key; the sink receives a
// trusted value from a local map, so taint does not reach exec.
const ALLOWED = { start: 'systemctl start app', stop: 'systemctl stop app' };

function apply(body) {
  const info = JSON.parse(body);
  const command = ALLOWED[info.action];
  if (command) {
    exec(command);
  }
}

module.exports = { apply };
