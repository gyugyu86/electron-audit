const { BrowserWindow } = require('electron');
const { getOptions } = require('./options.js');

// getOptions is defined in another file — cross-function/file tracking is out
// of scope, so this stays dynamic (heuristic), never silently resolved.
module.exports = () => new BrowserWindow(getOptions());
