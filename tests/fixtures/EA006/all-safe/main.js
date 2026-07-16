const { BrowserWindow } = require('electron');
function createA() {
  return new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
function createB() {
  return new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
module.exports = { createA, createB };
