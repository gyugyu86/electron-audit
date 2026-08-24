const { ipcMain } = require('electron');
const fs = require('fs-extra');

// Family C (ipc arg after event) -> fs-path sink, reached through a wrapper
// rather than through `fs` itself. fs-extra re-exports the fs API under the
// same names, so `fs.writeFile` here is the same sink it would be on fs — the
// only difference is the module the binding came from. Before wrappers were
// recognized this file produced nothing at all.
ipcMain.handle('write-file', (event, userPath, data) => {
  fs.writeFile(userPath, data);
});
