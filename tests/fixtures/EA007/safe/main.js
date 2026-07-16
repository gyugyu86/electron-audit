const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { enableRemoteModule: false } });
new BrowserWindow({ webPreferences: { nodeIntegration: false } });
