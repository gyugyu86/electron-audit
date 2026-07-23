import { describe, expect, it } from 'vitest';
import { parse } from '@babel/parser';
import { collectImportBindings, normalizeModuleSource } from '../../src/core/rules/shared/importBindings.js';

function bindingsOf(source: string): ReturnType<typeof collectImportBindings> {
  return collectImportBindings(parse(source, { sourceType: 'unambiguous', plugins: ['typescript', 'jsx'] }));
}

describe('normalizeModuleSource', () => {
  it("strips the node: builtin prefix ('node:child_process' -> 'child_process')", () => {
    expect(normalizeModuleSource('node:child_process')).toBe('child_process');
  });

  it("preserves a subpath ('node:fs/promises' -> 'fs/promises', not 'fs')", () => {
    expect(normalizeModuleSource('node:fs/promises')).toBe('fs/promises');
  });

  it('leaves an un-prefixed builtin unchanged', () => {
    expect(normalizeModuleSource('fs')).toBe('fs');
  });

  it('leaves a third-party package untouched (npm names never carry the prefix)', () => {
    expect(normalizeModuleSource('axios')).toBe('axios');
    // Only a leading `node:` is a prefix; anything else is part of the name.
    expect(normalizeModuleSource('some-node:thing')).toBe('some-node:thing');
  });
});

describe('collectImportBindings normalizes the source', () => {
  it('records a node:-prefixed ESM import under the bare module name', () => {
    const bindings = bindingsOf("import { exec } from 'node:child_process';");
    expect(bindings.get('exec')).toEqual({ source: 'child_process', importedName: 'exec' });
  });

  it('records a node:-prefixed require under the bare module name', () => {
    const bindings = bindingsOf("const cp = require('node:fs/promises');");
    expect(bindings.get('cp')).toEqual({ source: 'fs/promises', importedName: 'default' });
  });

  it('does not alter a third-party source', () => {
    const bindings = bindingsOf("import axios from 'axios';");
    expect(bindings.get('axios')?.source).toBe('axios');
  });
});
