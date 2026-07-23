// The `node:` builtin-protocol prefix must be recognized the same as the bare
// `child_process` — modern code prefers this spelling.
import { exec } from 'node:child_process';

export function run(userInput) {
  exec(`echo ${userInput}`);
}
