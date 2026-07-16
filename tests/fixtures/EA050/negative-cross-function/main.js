const { exec } = require('child_process');

// The accepted false-negative boundary: source and sink live in DIFFERENT
// functions. `data` is tainted in loadAndRun, but it's passed across a
// function-call boundary into runCommand, whose `cmd` param this tool does
// not trace. EA050 must stay silent here — locking that boundary as a
// regression so a future scope-widening that reintroduces cross-function
// tracking (and its false positives) trips this test.
function runCommand(cmd) {
  exec(cmd);
}

async function loadAndRun() {
  const res = await fetch('https://example.com/cmd');
  const data = await res.json();
  runCommand(data.cmd);
}

module.exports = { loadAndRun };
