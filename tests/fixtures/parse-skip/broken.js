const { BrowserWindow = require('electron');

function createWindow( {
  return new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
