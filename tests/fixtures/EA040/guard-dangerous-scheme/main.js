const { shell } = require('electron');

// A scheme CHECK exists, but it restricts to file: — the presence of a
// protocol comparison is not the same as restricting to safe schemes.
// Must keep firing.
function open(url) {
  const { protocol } = new URL(url);
  if (protocol === 'file:') {
    shell.openExternal(url);
  }
}

module.exports = { open };
