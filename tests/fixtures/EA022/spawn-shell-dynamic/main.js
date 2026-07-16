const { spawn } = require('child_process');

function run(useShell, userInput) {
  spawn(`echo ${userInput}`, { shell: useShell });
}

module.exports = { run };
