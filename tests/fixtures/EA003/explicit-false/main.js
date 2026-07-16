const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { sandbox: false } });
