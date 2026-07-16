const { BrowserWindow } = require('electron');
function createWindow() {
  return new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
module.exports = { createWindow };
