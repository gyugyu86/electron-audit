import type { BrowserWindowCallSite } from '../../ast/webPreferencesExtractor.js';

// A window is "dangerous" if it explicitly opts into a Node-exposing config.
// Used by EA006 (cross-window mismatch) and to gate EA041 absence.
export function isDangerousWindow(site: BrowserWindowCallSite): boolean {
  return (
    site.webPreferences.nodeIntegration.state === 'explicit-true' ||
    site.webPreferences.contextIsolation.state === 'explicit-false'
  );
}

// A window is "clearly safe" only when both switches are known-safe —
// explicitly safe or absent (relying on the modern secure default). A
// `dynamic` value is neither clearly safe nor clearly dangerous, so it does
// not count as safe here (avoids using an unknown as the "safe side" of a
// mismatch, which would be a false positive).
export function isClearlySafeWindow(site: BrowserWindowCallSite): boolean {
  const nodeIntegration = site.webPreferences.nodeIntegration.state;
  const contextIsolation = site.webPreferences.contextIsolation.state;
  return (
    (nodeIntegration === 'explicit-false' || nodeIntegration === 'absent') &&
    (contextIsolation === 'explicit-true' || contextIsolation === 'absent')
  );
}
