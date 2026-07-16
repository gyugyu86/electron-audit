const { session } = require('electron');
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      'Content-Security-Policy': ["img-src 'self' https://*.cdn.com"],
    },
  });
});
