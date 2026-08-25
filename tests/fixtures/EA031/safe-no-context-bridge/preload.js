const { ipcRenderer } = require('electron');

// ipcRenderer used with a channel argument, but nothing is exposed across the
// bridge, so no renderer-reachable surface exists. Internal helpers taking a
// channel are not this rule's subject.
function relay(channel, payload) {
  ipcRenderer.send(channel, payload);
}

module.exports = { relay };
