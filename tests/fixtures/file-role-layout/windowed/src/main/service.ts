// The ordinary case the layout is for: no manifest entry to go by, no marker
// in the filename, but the directory says main process.
import { exec } from 'node:child_process';

export function open(target: string): void {
  exec(`open ${target}`);
}
