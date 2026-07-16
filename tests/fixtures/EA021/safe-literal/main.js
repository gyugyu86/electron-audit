const sudo = require('sudo-prompt');

function elevateAndRun() {
  sudo.exec('some-fixed-tool --flag', { name: 'MyApp' }, () => {});
}

module.exports = { elevateAndRun };
