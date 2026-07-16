const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { allowRunningInsecureContent: true } });
