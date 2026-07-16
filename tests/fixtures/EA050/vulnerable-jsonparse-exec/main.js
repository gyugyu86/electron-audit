const { exec } = require('child_process');

// Family A: JSON.parse result flows to exec in the same scope.
function apply(body) {
  const info = JSON.parse(body);
  exec(`./run ${info.target}`);
}

module.exports = { apply };
