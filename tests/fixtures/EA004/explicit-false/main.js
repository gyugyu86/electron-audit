const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { webSecurity: false } });
