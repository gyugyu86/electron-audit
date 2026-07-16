import { describe, expect, it } from 'vitest';
import { findUnsafeCspHits, findWildcardCspDirectives } from '../../src/core/rules/shared/cspSites.js';

describe('findUnsafeCspHits (directive-graded severity)', () => {
  it("grades unsafe-inline HIGH in script-src / default-src", () => {
    expect(findUnsafeCspHits("script-src 'unsafe-inline'")).toEqual([
      { directive: 'script-src', severity: 'high', keywords: ["'unsafe-inline'"] },
    ]);
    expect(findUnsafeCspHits("default-src 'unsafe-inline'")[0]?.severity).toBe('high');
  });

  it('grades unsafe-inline MEDIUM in non-script directives (style-src, img-src)', () => {
    expect(findUnsafeCspHits("style-src 'unsafe-inline'")).toEqual([
      { directive: 'style-src', severity: 'medium', keywords: ["'unsafe-inline'"] },
    ]);
    expect(findUnsafeCspHits("img-src 'unsafe-inline'")[0]?.severity).toBe('medium');
  });

  it('grades unsafe-eval HIGH regardless of directive', () => {
    expect(findUnsafeCspHits("style-src 'unsafe-eval'")[0]).toMatchObject({ severity: 'high' });
    expect(findUnsafeCspHits("script-src 'unsafe-eval'")[0]?.severity).toBe('high');
  });

  it('splits a directive with both a high and a medium keyword into two hits', () => {
    // 'unsafe-eval' (always high) + 'unsafe-inline' in style-src (medium)
    const hits = findUnsafeCspHits("style-src 'unsafe-eval' 'unsafe-inline'");
    expect(hits).toContainEqual({ directive: 'style-src', severity: 'high', keywords: ["'unsafe-eval'"] });
    expect(hits).toContainEqual({ directive: 'style-src', severity: 'medium', keywords: ["'unsafe-inline'"] });
  });

  it('does not flag a safe CSP, and case-folds keywords', () => {
    expect(findUnsafeCspHits("default-src 'self'")).toEqual([]);
    expect(findUnsafeCspHits("script-src 'UNSAFE-INLINE'")[0]?.severity).toBe('high');
  });
});

describe('findWildcardCspDirectives (exact-token only)', () => {
  it('flags an exact "*" source but not a partial wildcard', () => {
    expect(findWildcardCspDirectives('default-src *')).toEqual(['default-src']);
    expect(findWildcardCspDirectives('default-src *.foo.com https://*.cdn.com')).toEqual([]);
  });
});
