const { BrowserWindow } = require('electron');

// A helper that returns a genuinely dangerous config — resolution must NOT
// hide this; EA001 must fire at high confidence, exactly as if inline.
const getOptions = () => ({
  webPreferences: { nodeIntegration: true },
});

module.exports = () => new BrowserWindow(getOptions());
