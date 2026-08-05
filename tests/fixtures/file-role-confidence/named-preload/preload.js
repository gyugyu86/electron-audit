// Determined by filename: a file called preload is a preload script.
const { exec } = require('child_process');

module.exports.probe = (name) => exec(`which ${name}`);
