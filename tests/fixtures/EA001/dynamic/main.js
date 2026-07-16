const { BrowserWindow } = require('electron');

const enableNodeIntegration = process.env.ENABLE_NODE_INTEGRATION === 'true';

function createWindow() {
  return new BrowserWindow({
    webPreferences: {
      nodeIntegration: enableNodeIntegration,
    },
  });
}

module.exports = { createWindow };
