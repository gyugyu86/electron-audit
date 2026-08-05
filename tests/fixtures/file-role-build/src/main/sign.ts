// A build-looking FILENAME inside an application source tree. `sign.ts` is on
// the build-tooling name list, but `src/main/` says this runs in the app, so
// the name must not win — the same asymmetry as the `src/.../scripts/` case.
import { execSync } from 'node:child_process';

export function signDocument(documentPath: string): void {
  // EA020 — reported as app code, not as build tooling.
  execSync(`gpg --sign ${documentPath}`);
}
