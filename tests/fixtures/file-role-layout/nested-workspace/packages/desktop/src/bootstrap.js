// The root manifest is a workspace stub with no `main`. The one that names an
// entry point sits a package down, which is where the app actually lives.
// Deliberately named so neither the filename check nor the directory layout
// could answer — only the nested manifest can.
const { exec } = require('child_process');

module.exports.launch = (tool) => exec(`${tool} --serve`);
