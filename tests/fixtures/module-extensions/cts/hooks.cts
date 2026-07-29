// The CommonJS TypeScript half — also JSX-off, also previously unreachable
// end to end. Carries a generic for the same reason `build.mts` does.
const { execSync } = require('child_process');

const pick = <T>(values: T[]): T => values[0];

function afterPack(outDirs: string[]): void {
  // EA020
  execSync(`codesign --force ${pick(outDirs)}`);
}

module.exports = { afterPack };
