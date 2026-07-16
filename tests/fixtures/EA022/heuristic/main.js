const { exec } = require('child_process');

function run(userCommand) {
  exec(userCommand);
}

module.exports = { run };
