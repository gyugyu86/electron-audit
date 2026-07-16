import { describe, expect, it } from 'vitest';
import { parseSource } from '../../src/core/parser.js';
import { extractWebPreferences } from '../../src/core/ast/webPreferencesExtractor.js';

// EA006 (cross-window mismatch, M2) will trust this extractor's per-window
// output without re-deriving it, so its state classification is verified
// standalone here across several windows in one file.
const SOURCE = `
const { BrowserWindow } = require('electron');

// window 1: explicit unsafe combo
const win1 = new BrowserWindow({
  webPreferences: { nodeIntegration: true, contextIsolation: false },
});

// window 2: safe, explicit, with a preload path
const win2 = new BrowserWindow({
  webPreferences: { nodeIntegration: false, contextIsolation: true, preload: 'preload.js' },
});

// window 3: no webPreferences at all -> every field absent
const win3 = new BrowserWindow({ width: 400 });

// window 4: nodeIntegration comes from a reassignable 'let', not 'const' ->
// must NOT be folded, so it stays dynamic
let flag = true;
const win4 = new BrowserWindow({
  webPreferences: { nodeIntegration: flag },
});

// window 5: nodeIntegration comes from a same-file 'const' -> folds to explicit
const isDev = true;
const win5 = new BrowserWindow({
  webPreferences: { nodeIntegration: isDev },
});
`;

describe('extractWebPreferences', () => {
  it('returns one call site per BrowserWindow construction with correct per-field state', () => {
    const parsed = parseSource(SOURCE, 'virtual.js');
    if (!parsed) {
      throw new Error('fixture source failed to parse');
    }

    const sites = extractWebPreferences(parsed.ast, 'virtual.js');
    expect(sites).toHaveLength(5);

    expect(sites[0].webPreferences.nodeIntegration).toEqual({ state: 'explicit-true' });
    expect(sites[0].webPreferences.contextIsolation).toEqual({ state: 'explicit-false' });

    expect(sites[1].webPreferences.nodeIntegration).toEqual({ state: 'explicit-false' });
    expect(sites[1].webPreferences.contextIsolation).toEqual({ state: 'explicit-true' });
    expect(sites[1].webPreferences.preload).toEqual({ state: 'explicit', value: 'preload.js' });

    expect(sites[2].webPreferences.nodeIntegration).toEqual({ state: 'absent' });
    expect(sites[2].webPreferences.preload).toEqual({ state: 'absent' });

    expect(sites[3].webPreferences.nodeIntegration).toEqual({ state: 'dynamic' });

    expect(sites[4].webPreferences.nodeIntegration).toEqual({ state: 'explicit-true' });
  });
});
