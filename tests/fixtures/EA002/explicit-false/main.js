const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { contextIsolation: false } });
