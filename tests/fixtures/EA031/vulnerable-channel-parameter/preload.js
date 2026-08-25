const { contextBridge, ipcRenderer } = require('electron');

// Every forwarding method gets its own exposed function on its own line, so a
// method removed from the rule's list fails that line's assertion alone.
contextBridge.exposeInMainWorld('api', {
  send: (channel, ...args) => ipcRenderer.send(channel, ...args),
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  sendSync: (channel, ...args) => ipcRenderer.sendSync(channel, ...args),
  sendToHost: (channel, ...args) => ipcRenderer.sendToHost(channel, ...args),
  on: (channel, listener) => ipcRenderer.on(channel, listener),
  once: (channel, listener) => ipcRenderer.once(channel, listener),
});
