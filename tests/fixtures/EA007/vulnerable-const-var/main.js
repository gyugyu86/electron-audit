const { BrowserWindow } = require('electron');
const opts = { webPreferences: { nodeIntegration: false, enableRemoteModule: true } };
new BrowserWindow(opts);
