const { exec } = require('child_process');
const fs = require('node:fs');

// Local config, not external input: JSON.parse of a local fs read is
// excluded, so this stays silent.
function apply() {
  const cfg = JSON.parse(fs.readFileSync('config.json', 'utf8'));
  exec(`./run ${cfg.target}`);
}

module.exports = { apply };
