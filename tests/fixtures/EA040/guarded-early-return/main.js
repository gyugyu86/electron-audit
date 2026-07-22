const { shell } = require('electron');

// Form C: early-return guard clause dominating the call below it.
function open(url) {
  const { protocol } = new URL(url);
  if (!['http:', 'https:'].includes(protocol)) return;
  shell.openExternal(url);
}

module.exports = { open };
