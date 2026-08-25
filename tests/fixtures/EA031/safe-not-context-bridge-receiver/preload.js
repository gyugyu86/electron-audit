const { ipcRenderer } = require('electron');

// A local double with a method of the same name. `exposeInMainWorld` only
// crosses the context boundary when it is contextBridge's — on anything else
// it is an ordinary function call that exposes nothing, so the receiver has to
// be checked and not just the method name.
const fakeBridge = {
  exposeInMainWorld(name, api) {
    return { name, api };
  },
};

fakeBridge.exposeInMainWorld('api', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
});
