const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { nodeIntegration: false } });
