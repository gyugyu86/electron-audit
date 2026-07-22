const { shell } = require('electron');

// The safe condition wraps only the log — the call below runs regardless.
// Not dominated. Must keep firing.
function open(url) {
  if (['http:', 'https:'].includes(new URL(url).protocol)) {
    console.log(url);
  }
  shell.openExternal(url);
}

module.exports = { open };
