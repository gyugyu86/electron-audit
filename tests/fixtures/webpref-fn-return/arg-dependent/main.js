const { BrowserWindow } = require('electron');

// The returned config depends on an argument — different call sites could pass
// different values, so the literal here is not a sound stand-in.
function getOptions(nodeIntegration) {
  return { webPreferences: { nodeIntegration } };
}

module.exports = () => new BrowserWindow(getOptions(true));
