const { shell } = require('electron');

// Form D: prefix literal pins the scheme.
function open(url) {
  if (url.startsWith('https://')) {
    shell.openExternal(url);
  }
}

module.exports = { open };
