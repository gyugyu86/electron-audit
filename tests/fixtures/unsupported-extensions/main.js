const { BrowserWindow } = require('electron');
// One analyzable file with one finding, so the test can show the count does
// not disturb detection: this EA001 must come through unchanged.
new BrowserWindow({ webPreferences: { nodeIntegration: true } });
