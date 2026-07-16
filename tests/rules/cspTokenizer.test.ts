import { describe, expect, it } from 'vitest';
import { tokenizeCsp } from '../../src/core/csp/cspTokenizer.js';

// EA011/012/013 trust this tokenizer, so its robustness is pinned directly.
describe('tokenizeCsp', () => {
  it('splits into directives then sources', () => {
    expect(tokenizeCsp("default-src 'self'; script-src 'self' 'unsafe-inline'")).toEqual([
      { name: 'default-src', sources: ["'self'"] },
      { name: 'script-src', sources: ["'self'", "'unsafe-inline'"] },
    ]);
  });

  it('lowercases the directive name but preserves source case', () => {
    expect(tokenizeCsp('Default-Src HTTPS://Example.COM')).toEqual([
      { name: 'default-src', sources: ['HTTPS://Example.COM'] },
    ]);
  });

  it('keeps duplicate directives as separate entries', () => {
    expect(tokenizeCsp("default-src 'self'; default-src *")).toEqual([
      { name: 'default-src', sources: ["'self'"] },
      { name: 'default-src', sources: ['*'] },
    ]);
  });

  it('tolerates leading/trailing and internal extra whitespace', () => {
    expect(tokenizeCsp("   default-src   'self'   ;   script-src 'self'   ")).toEqual([
      { name: 'default-src', sources: ["'self'"] },
      { name: 'script-src', sources: ["'self'"] },
    ]);
  });

  it('returns [] for empty / semicolons-only / whitespace-only input without throwing', () => {
    expect(tokenizeCsp('')).toEqual([]);
    expect(tokenizeCsp(';;;')).toEqual([]);
    expect(tokenizeCsp('   ')).toEqual([]);
  });

  it('handles a valueless directive', () => {
    expect(tokenizeCsp('upgrade-insecure-requests')).toEqual([
      { name: 'upgrade-insecure-requests', sources: [] },
    ]);
  });
});
