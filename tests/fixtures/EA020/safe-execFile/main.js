const { execFile } = require('child_process');

function killProcess(pid) {
  execFile('kill', [String(pid)]);
}

module.exports = { killProcess };
