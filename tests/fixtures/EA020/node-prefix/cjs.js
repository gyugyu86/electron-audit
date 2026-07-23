// Same via require('node:child_process') — the inline/require path must also
// normalize the prefix.
const cp = require('node:child_process');

module.exports.run = (userInput) => cp.execSync(`ls ${userInput}`);
