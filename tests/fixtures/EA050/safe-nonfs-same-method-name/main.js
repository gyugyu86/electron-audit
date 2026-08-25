const { ipcMain } = require('electron');

// `remove`, `move` and `copy` are ordinary words. Objects that are not the
// filesystem use them constantly — across the measured corpora `remove` alone
// is called hundreds of times on stores, hosts and collections. The sink check
// resolves the receiver to a filesystem module before it agrees, so none of
// these is a finding no matter what the handler's argument does.
const registry = new Map();
const layers = { move: (id) => id, copy: (id) => id, remove: (id) => id };

ipcMain.handle('drop-entry', (event, key) => registry.delete(key));
ipcMain.handle('drop-layer', (event, key) => layers.remove(key));
ipcMain.handle('shift-layer', (event, key) => layers.move(key));
ipcMain.handle('clone-layer', (event, key) => layers.copy(key));
