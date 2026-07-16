const { spawn } = require('child_process');

function run(userInput) {
  spawn('echo', [userInput]);
}

module.exports = { run };
