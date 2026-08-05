// Genuine build tooling: a `scripts` directory at the project root, with no
// application source directory above it. This is the positive case — the one
// the role exists to mark.
import { execSync } from 'node:child_process';

export function sign(scriptPath, target) {
  // EA020, and correctly so: the command really is assembled by interpolation.
  // The role only says where it runs, never whether it is a problem.
  execSync(`bash "${scriptPath}" "${target}"`);
}
