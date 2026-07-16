const { spawn } = require('child_process');

function run(userInput) {
  spawn(`echo ${userInput}`, { shell: true });
}

module.exports = { run };
