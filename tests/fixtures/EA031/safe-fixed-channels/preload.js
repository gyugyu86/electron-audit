const { contextBridge, ipcRenderer } = require('electron');

// The channel is decided here, in the preload — which is the whole point of
// the boundary. Nothing to report.
contextBridge.exposeInMainWorld('api', {
  readSettings: () => ipcRenderer.invoke('settings:read'),
  saveSettings: (settings) => ipcRenderer.invoke('settings:save', settings),
  onThemeChanged: (listener) => ipcRenderer.on('theme:changed', (_event, theme) => listener(theme)),
});
