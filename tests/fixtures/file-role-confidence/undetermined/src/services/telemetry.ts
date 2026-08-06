// Nothing here says which process this runs in. The manifest points at a
// bundler output that is not in source, the filename carries no marker, and
// `src/services/` is not one of the directories a project uses to separate
// the processes.
//
// So the role stays unreported. This fixture holds the property that an
// unknown role is shown as nothing rather than guessed at — the directory
// layout can now answer many files, and this is one it must not answer.
import { exec } from 'node:child_process';

export function report(endpoint: string): void {
  exec(`curl ${endpoint}`);
}
