const { BrowserWindow } = require('electron');
function createWindow(startUrl) {
  const win = new BrowserWindow();
  win.loadURL(startUrl);
  return win;
}
module.exports = { createWindow };
