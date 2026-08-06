// Same, for the renderer side.
import { exec } from 'node:child_process';

export function preview(file: string): void {
  exec(`qlmanage -p ${file}`);
}
