const { session } = require('electron');
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      'Content-Security-Policy': ["default-src 'self'; script-src 'self'"],
    },
  });
});
