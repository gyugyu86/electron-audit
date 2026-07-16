const { BrowserWindow, session } = require('electron');
function createWindow() {
  return new BrowserWindow({ webPreferences: { contextIsolation: true } });
}
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': ["default-src 'self'"],
    },
  });
});
module.exports = { createWindow };
