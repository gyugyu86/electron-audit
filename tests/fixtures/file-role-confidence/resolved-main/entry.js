// The determined case, kept deliberately free of filename hints: `entry.js`
// says nothing on its own, so the only reason this resolves is the manifest
// naming it as the entry point. That isolates the manifest path from the
// filename heuristic.
const { exec } = require('child_process');

module.exports.run = (target) => exec(`open ${target}`);
