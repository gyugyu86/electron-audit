const { contextBridge, ipcRenderer } = require('electron');

// A parameter reaching ipcRenderer is ordinary and correct — that is how a
// bridge passes data. Only a parameter landing in the CHANNEL position is the
// problem. If this fires, the rule is flagging every exposed function rather
// than the pattern it is about.
contextBridge.exposeInMainWorld('api', {
  saveNote: (body) => ipcRenderer.send('note:save', body),
  search: (query, limit) => ipcRenderer.invoke('note:search', query, limit),
});
