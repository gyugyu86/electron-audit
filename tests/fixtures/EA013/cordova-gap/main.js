const { session } = require('electron');
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      'Content-Security-Policy': ["default-src 'self' gap: https://ssl.gstatic.com"],
    },
  });
});
