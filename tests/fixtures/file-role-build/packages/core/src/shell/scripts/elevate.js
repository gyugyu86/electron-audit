// THE MISCLASSIFICATION THIS FIXTURE EXISTS TO PREVENT.
//
// The path contains a `scripts` directory, but it sits under `src/`, and this
// is application code: it runs while the app runs, and it asks the OS for a
// root shell. The shape is taken from a real desktop app measured during the
// investigation, where a naive "any directory named scripts" rule labelled it
// build tooling.
//
// Getting that wrong would undo work already done: this is exactly the
// privileged-execution case that was promoted to EA021 so the report would
// stop describing it as an ordinary command injection. Telling a reader it is
// a packaging concern would hide a live privilege-escalation path.
const sudoPrompt = require('@vscode/sudo-prompt');

function enableLoopback(toolPath) {
  // EA021: privileged exec with a command string that is not a static literal.
  sudoPrompt.exec(`"${toolPath}" --enable`, { name: 'Loopback' }, (error) => {
    if (error) {
      throw error;
    }
  });
}

module.exports = { enableLoopback };
