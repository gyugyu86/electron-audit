const { BrowserWindow } = require('electron');

function createWindow() {
  return new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
    },
  });
}

module.exports = { createWindow };
