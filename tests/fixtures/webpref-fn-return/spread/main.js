const { BrowserWindow } = require('electron');

const base = { show: false };

// A spread of an unknowable base could carry or override fields — not resolved.
function getOptions() {
  return { ...base, webPreferences: { nodeIntegration: true } };
}

module.exports = () => new BrowserWindow(getOptions());
