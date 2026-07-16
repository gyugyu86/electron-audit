const { ipcMain } = require('electron');
const fs = require('node:fs');

// The event object (first param) is NOT untrusted input — only the args
// after it are. A member of `event` reaching a sink must stay silent.
ipcMain.handle('read', (event) => {
  fs.readFile(event.somePath, 'utf8', () => {});
});
