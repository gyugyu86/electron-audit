const { BrowserWindow } = require('electron');
function createWindow() {
  return new BrowserWindow({ webPreferences: { contextIsolation: true } });
}
module.exports = { createWindow };
