// THE CASE THIS FIXTURE PINS.
//
// This is main-process code — it lives under src/main/ and the path says so —
// but the classifier cannot prove it. The manifest's `main` points at a
// bundler output that does not exist in source, so the path never matches,
// and the filename carries no marker either. The classifier therefore falls
// back, and the fallback is always `renderer`.
//
// Reporting that fallback put "[renderer]" on a main-process file, on the
// same line as a path reading src/main/ — the report contradicting itself.
// A real project measured during the investigation had exactly this shape.
// The role must now be absent instead.
import { exec } from 'node:child_process';

export function launchHelper(toolPath: string): void {
  exec(`${toolPath} --serve`);
}
