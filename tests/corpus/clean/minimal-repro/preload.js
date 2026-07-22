// vendored test fixture — not our code, source: https://github.com/electron/minimal-repro (formerly electron-quick-start) @ b4f681add21303def253f4f1a36cfe28d44787fe
// license: CC0-1.0 (see ./LICENSE.md and ../PROVENANCE.md). Body below is the upstream file, unmodified except for this header.

/**
 * The preload script runs before `index.html` is loaded
 * in the renderer. It has access to web APIs as well as
 * Electron's renderer process modules and some polyfilled
 * Node.js functions.
 *
 * https://www.electronjs.org/docs/latest/tutorial/sandbox
 */
window.addEventListener('DOMContentLoaded', () => {
  const replaceText = (selector, text) => {
    const element = document.getElementById(selector)
    if (element) element.innerText = text
  }

  for (const type of ['chrome', 'node', 'electron']) {
    replaceText(`${type}-version`, process.versions[type])
  }
})
