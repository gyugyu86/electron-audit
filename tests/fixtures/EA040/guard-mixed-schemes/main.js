const { shell } = require('electron');

// Allowlist is polluted with a dangerous scheme — the allowed set is not a
// subset of http/https. Must keep firing.
function open(url) {
  const { protocol } = new URL(url);
  if (['http:', 'https:', 'file:'].includes(protocol)) {
    shell.openExternal(url);
  }
}

module.exports = { open };
