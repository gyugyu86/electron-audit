const { shell } = require('electron');
function open(url) {
  shell.openExternal(url);
}
module.exports = { open };
