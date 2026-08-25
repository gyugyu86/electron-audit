const { contextBridge, ipcRenderer } = require('electron');

// A pass-through exposed through a const rather than inline. The rule does
// NOT report this, on purpose: reading const-held objects was measured and
// every real case it reached had already guarded the channel against an
// allowlist, so the wider read bought a false-positive class and no true
// finding. This fixture pins that boundary — if it ever starts firing, the
// widening was reintroduced without the guard recognition that has to come
// with it.
const api = {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
};

contextBridge.exposeInMainWorld('api', api);
