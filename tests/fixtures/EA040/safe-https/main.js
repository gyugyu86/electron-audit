const { shell } = require('electron');
function open() {
  shell.openExternal('https://example.com/docs');
}
module.exports = { open };
