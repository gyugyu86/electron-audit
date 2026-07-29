// `.mjs` is ESM by extension no matter what the package's "type" field says,
// and it is where Electron projects put packaging and code-signing scripts.
// This is the shape the extension gap was hiding.
import { execSync } from 'node:child_process';

export function signMacOS(scriptPath, target) {
  // EA020: neither value is a static literal, so the shell command is
  // assembled from input this analyzer cannot prove safe.
  execSync(`bash "${scriptPath}" "${target}"`);
}
