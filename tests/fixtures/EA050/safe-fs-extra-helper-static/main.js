const { ipcMain } = require('electron');
const fs = require('fs-extra');

// Recognizing the helper must not make every call through it a finding — the
// handler's argument never reaches the path.
ipcMain.handle('reset-cache', (event) => fs.emptyDir('/tmp/app-cache'));
