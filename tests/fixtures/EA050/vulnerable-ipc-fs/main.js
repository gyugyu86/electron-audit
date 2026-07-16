const { ipcMain } = require('electron');
const fs = require('node:fs');

// Family C (ipc arg after event) -> fs-path sink.
ipcMain.handle('read-file', (event, userPath) => {
  fs.readFile(userPath, 'utf8', () => {});
});
