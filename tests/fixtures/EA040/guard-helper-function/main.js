const { shell } = require('electron');

// Validation split into a helper — cross-function tracking is outside this
// tool's stated scope, so the heuristic finding is retained by design.
function isSafeUrl(url) {
  const { protocol } = new URL(url);
  return ['http:', 'https:'].includes(protocol);
}

function open(url) {
  if (isSafeUrl(url)) {
    shell.openExternal(url);
  }
}

module.exports = { open };
