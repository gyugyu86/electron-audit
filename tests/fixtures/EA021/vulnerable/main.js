const sudo = require('sudo-prompt');

function elevateAndRun(url) {
  sudo.exec(`some-tool --target=${url}`, { name: 'MyApp' }, () => {});
}

module.exports = { elevateAndRun };
