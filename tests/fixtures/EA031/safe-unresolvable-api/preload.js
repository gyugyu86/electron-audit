const { contextBridge, ipcRenderer } = require('electron');

// The exposed object comes back from a call, so what it contains cannot be
// read here. This rule reports at high confidence, so an API surface it
// cannot see is one it says nothing about — a miss, on purpose, rather than a
// guess.
function buildApi() {
  return { invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args) };
}

contextBridge.exposeInMainWorld('api', buildApi());
