// An unusual layout, on purpose: the manifest names this file as the entry
// point while it sits under renderer/. A declared entry point is a fact and
// the directory name is a convention, so the fact has to win.
const { exec } = require('child_process');

module.exports.run = (target) => exec(`open ${target}`);
