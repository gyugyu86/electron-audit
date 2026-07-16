const { BrowserWindow } = require('electron');
function createWindow() {
  const win = new BrowserWindow();
  win.loadURL('http://localhost:3000');
  return win;
}
module.exports = { createWindow };
