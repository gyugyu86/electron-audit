const { shell } = require('electron');
function open() {
  shell.openExternal('file:///etc/passwd');
}
module.exports = { open };
