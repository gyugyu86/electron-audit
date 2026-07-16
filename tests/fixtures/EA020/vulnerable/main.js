const { exec } = require('child_process');

function killProcess(pid) {
  exec(`kill ${pid}`);
}

module.exports = { killProcess };
