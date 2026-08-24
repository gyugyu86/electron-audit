const { ipcMain } = require('electron');
const fs = require('fs-extra');

// Recognizing the wrapper must not make every call through it a finding. The
// path here is a static literal and the handler's argument never reaches it,
// so nothing is reported.
ipcMain.handle('read-manifest', (event) => {
  fs.readFile('manifest.json', 'utf8', () => {});
});
