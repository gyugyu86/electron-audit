const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { enableRemoteModule: true } });
