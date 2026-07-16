const { exec } = require('child_process');

function listFiles() {
  exec('ls -la /tmp');
}

module.exports = { listFiles };
