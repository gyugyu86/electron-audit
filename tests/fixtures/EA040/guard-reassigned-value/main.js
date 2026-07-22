const { shell } = require('electron');

// The value is reassigned after the check — the guard saw a different value
// than the sink. Must keep firing.
function open(url, fallback) {
  const { protocol } = new URL(url);
  if (['http:', 'https:'].includes(protocol)) {
    url = fallback;
    shell.openExternal(url);
  }
}

module.exports = { open };
