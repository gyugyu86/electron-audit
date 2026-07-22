const { shell } = require('electron');

// Form B (the fiddle shape): destructured protocol + inline-array includes,
// inside try/catch like real code.
function open(url) {
  try {
    const { protocol } = new URL(url);
    if (['http:', 'https:'].includes(protocol)) {
      shell.openExternal(url);
    }
  } catch {}
}

module.exports = { open };
