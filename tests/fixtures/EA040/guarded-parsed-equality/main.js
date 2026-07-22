const { shell } = require('electron');

// Form A: URL parse into a const, protocol equality — plus the inline
// variant with no intermediate variable. Both are dominated by a safe guard.
function open(url) {
  const parsed = new URL(url);
  if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
    shell.openExternal(url);
  }
}

function openInline(url) {
  if (['http:', 'https:'].includes(new URL(url).protocol)) {
    shell.openExternal(url);
  }
}

module.exports = { open, openInline };
