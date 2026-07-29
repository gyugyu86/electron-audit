// `.cjs` is CommonJS by extension even inside a `"type": "module"` package —
// the other half of the dual-module world, and just as unscanned before.
const { exec } = require('child_process');

module.exports.notarize = (bundleId) => {
  // EA020
  exec(`xcrun notarytool submit ${bundleId}`);
};
