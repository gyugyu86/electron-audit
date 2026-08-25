const { ipcMain } = require('electron');
const fs = require('fs-extra');

// fs-extra's own helpers are the same kind of sink as the vanilla names: a
// renderer-supplied path handed to emptyDir is a recursive delete, and to
// outputFile an arbitrary write.
//
// Every name added to the sink list gets its own handler here, Sync siblings
// included, so removing any single name fails that name's case and no other.
// A list entry nothing exercises is one a later edit can delete silently.
ipcMain.handle('output-file', (event, userPath, data) => fs.outputFile(userPath, data));
ipcMain.handle('output-file-sync', (event, userPath, data) => fs.outputFileSync(userPath, data));
ipcMain.handle('output-json', (event, userPath, obj) => fs.outputJson(userPath, obj));
ipcMain.handle('output-json-sync', (event, userPath, obj) => fs.outputJsonSync(userPath, obj));
ipcMain.handle('write-json', (event, userPath, obj) => fs.writeJson(userPath, obj));
ipcMain.handle('write-json-sync', (event, userPath, obj) => fs.writeJsonSync(userPath, obj));
ipcMain.handle('read-json', (event, userPath) => fs.readJson(userPath));
ipcMain.handle('read-json-sync', (event, userPath) => fs.readJsonSync(userPath));
ipcMain.handle('remove', (event, userPath) => fs.remove(userPath));
ipcMain.handle('remove-sync', (event, userPath) => fs.removeSync(userPath));
ipcMain.handle('empty-dir', (event, userPath) => fs.emptyDir(userPath));
ipcMain.handle('empty-dir-sync', (event, userPath) => fs.emptyDirSync(userPath));
ipcMain.handle('move', (event, src, dest) => fs.move(src, dest));
ipcMain.handle('move-sync', (event, src, dest) => fs.moveSync(src, dest));
ipcMain.handle('copy', (event, src, dest) => fs.copy(src, dest));
ipcMain.handle('copy-sync', (event, src, dest) => fs.copySync(src, dest));
