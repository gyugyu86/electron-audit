const { spawn } = require('child_process');

function run(useShell) {
  spawn('echo hello', { shell: useShell });
}

module.exports = { run };
