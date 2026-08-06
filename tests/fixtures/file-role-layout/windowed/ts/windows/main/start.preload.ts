// THE ORDERING DEFENCE.
//
// `ts/windows/` holds one directory per window — about, loading, permissions,
// main — so here `main` names the MAIN WINDOW, not the main process, and this
// file is its preload script. The shape is taken from a real app measured
// during the investigation, where the directory layout alone would have
// labelled four preload/renderer files as `main`.
//
// The filename check runs before the layout check, so `.preload.` answers
// first and the layout is never consulted. Reorder the two and this file
// starts claiming to be main-process code.
import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('api', {
  send: (channel: string, value: string) => ipcRenderer.send(channel, value),
});
