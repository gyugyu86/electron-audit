const { BrowserWindow } = require('electron');
const flag = process.env.X === '1';
new BrowserWindow({ webPreferences: { contextIsolation: flag } });
