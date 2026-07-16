const { BrowserWindow } = require('electron');
new BrowserWindow({ webPreferences: { contextIsolation: true } });
