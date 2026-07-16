// Synthetic "known-vulnerable" mini Electron app — reproduces one instance
// of each spec section 4 pattern in a single small project, so the whole
// rule set can be run against it and snapshotted together. Patterns whose
// rule isn't implemented yet are still here (commented with their intended
// ruleId) so the corpus "lights up" automatically as A/B/E/F groups land,
// instead of needing to be rewritten later.
const { app, BrowserWindow, shell, session } = require('electron');
const { exec } = require('child_process');
const sudo = require('sudo-prompt');
const path = require('path');

let mainWindow;

// EA001 (implemented): nodeIntegration:true exposed directly.
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1024,
    height: 768,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  mainWindow.loadFile('index.html');
}

// EA006 (not yet implemented): child window's webPreferences don't match
// the main window's — main window above is unsafe, this one is safe.
function createAboutWindow() {
  const about = new BrowserWindow({
    width: 400,
    height: 300,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  about.loadFile('about.html');
}

// EA011/EA012 (not yet implemented): CSP with unsafe-inline/unsafe-eval and
// a bare wildcard source.
function setContentSecurityPolicy() {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self' *; script-src 'self' 'unsafe-inline' 'unsafe-eval'"],
      },
    });
  });
}

// EA020 (implemented): template-interpolated command.
function killProcessByPid(pid) {
  exec(`kill ${pid}`);
}

// EA021 (implemented): the same shape as EA020, but through a sudo-prompt
// wrapper — should escalate to EA021 only, not double-report as EA020 too.
function installUpdate(url) {
  sudo.exec(`installer --source=${url}`, { name: 'SyntheticApp' }, () => {});
}

// EA040 (not yet implemented): shell.openExternal with no scheme allowlist.
function openExternalLink(url) {
  shell.openExternal(url);
}

app.whenReady().then(() => {
  createMainWindow();
  createAboutWindow();
  setContentSecurityPolicy();
});

module.exports = { killProcessByPid, installUpdate, openExternalLink };
