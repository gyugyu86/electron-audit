const { BrowserWindow } = require('electron');
function createWindow() {
  const win = new BrowserWindow();
  win.loadURL('http://example.com/app');
  return win;
}
module.exports = { createWindow };
