const { BrowserWindow } = require('electron');

// fiddle's getMainWindowOptions shape: a function declaration with leading
// const statements and a single unconditional object return.
function getMainWindowOptions() {
  const WIDTH = 1400;
  const HEIGHT = 900;
  return {
    width: WIDTH,
    height: HEIGHT,
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  };
}

module.exports = () => new BrowserWindow(getMainWindowOptions());
