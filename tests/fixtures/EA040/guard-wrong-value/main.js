const { shell } = require('electron');

// The protocol check inspects a DIFFERENT value than the one opened —
// not a guard. Must keep firing.
function open(url, otherUrl) {
  const { protocol } = new URL(otherUrl);
  if (['http:', 'https:'].includes(protocol)) {
    // unrelated bookkeeping
  }
  shell.openExternal(url);
}

module.exports = { open };
