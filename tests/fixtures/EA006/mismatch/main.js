const { BrowserWindow } = require('electron');
function createMain() {
  return new BrowserWindow({ webPreferences: { nodeIntegration: true } });
}
function createChild() {
  return new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });
}
module.exports = { createMain, createChild };
