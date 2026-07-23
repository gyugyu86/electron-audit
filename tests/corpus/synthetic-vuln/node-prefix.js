// node: builtin-protocol import — must be caught exactly like the bare
// `child_process` spelling. Regression lock for the prefix normalization so
// this false negative can't come back through the corpus.
const { exec } = require('node:child_process');

function openThing(userInput) {
  exec(`xdg-open ${userInput}`);
}

module.exports = { openThing };
