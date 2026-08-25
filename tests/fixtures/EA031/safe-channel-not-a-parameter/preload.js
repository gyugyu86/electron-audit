const { contextBridge, ipcRenderer } = require('electron');

// Two ways an identifier in the channel position can still be fixed by the
// preload: it can come from an enclosing scope, or a local can shadow the
// parameter. Neither lets the caller choose the channel, so neither is a
// finding — the rule has to resolve the identifier to a parameter of the
// exposed function itself.
const channel = 'notes:update';

contextBridge.exposeInMainWorld('api', {
  update: (payload) => ipcRenderer.send(channel, payload),
  refresh: (channel) => {
    {
      const channel = 'notes:refresh';
      ipcRenderer.send(channel, null);
    }
  },
});
