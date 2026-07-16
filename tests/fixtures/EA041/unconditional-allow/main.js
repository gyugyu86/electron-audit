const { BrowserWindow } = require('electron');
function createWindow() {
  const win = new BrowserWindow({ webPreferences: { contextIsolation: true } });
  win.webContents.setWindowOpenHandler(() => ({ action: 'allow' }));
  return win;
}
module.exports = { createWindow };
