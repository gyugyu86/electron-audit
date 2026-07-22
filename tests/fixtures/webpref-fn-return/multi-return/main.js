const { BrowserWindow } = require('electron');

// Branching with multiple returns — which object is returned is conditional,
// so it must not be resolved.
function getOptions() {
  if (process.env.SAFE) {
    return { webPreferences: { nodeIntegration: false } };
  }
  return { webPreferences: { nodeIntegration: true } };
}

module.exports = () => new BrowserWindow(getOptions());
