const { ipcMain } = require('electron');
const fs = require('graceful-fs');

// The same shape through the other recognized wrapper. graceful-fs is
// published as a drop-in replacement for fs, so the surface is identical.
ipcMain.handle('remove-file', (event, userPath) => {
  fs.unlink(userPath, () => {});
});
