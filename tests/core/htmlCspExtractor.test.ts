import { describe, expect, it } from 'vitest';
import { extractHtmlCspMetas } from '../../src/core/csp/htmlCspExtractor.js';

describe('extractHtmlCspMetas', () => {
  it('extracts a double-quoted content value with single-quoted CSP keywords', () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'">`;
    expect(extractHtmlCspMetas(html)).toEqual([{ line: 1, value: "default-src 'self'; script-src 'unsafe-inline'" }]);
  });

  it('extracts a single-quoted content value', () => {
    const html = `<meta http-equiv='Content-Security-Policy' content='default-src *'>`;
    expect(extractHtmlCspMetas(html)).toEqual([{ line: 1, value: 'default-src *' }]);
  });

  it('is case-insensitive on tag/attribute names and the http-equiv value', () => {
    const html = `<META HTTP-EQUIV="content-security-policy" CONTENT="default-src *">`;
    expect(extractHtmlCspMetas(html)).toEqual([{ line: 1, value: 'default-src *' }]);
  });

  it('handles attribute order (content before http-equiv)', () => {
    const html = `<meta content="default-src *" http-equiv="Content-Security-Policy">`;
    expect(extractHtmlCspMetas(html)).toEqual([{ line: 1, value: 'default-src *' }]);
  });

  it('ignores non-CSP meta tags and reports the correct line for the CSP one', () => {
    const html = [
      '<!DOCTYPE html>',
      '<html><head>',
      '<meta charset="UTF-8" />',
      '<meta http-equiv="Content-Security-Policy" content="default-src *" />',
      '</head></html>',
    ].join('\n');
    expect(extractHtmlCspMetas(html)).toEqual([{ line: 4, value: 'default-src *' }]);
  });

  it('extracts multiple CSP meta tags', () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">\n<meta http-equiv="Content-Security-Policy" content="img-src *">`;
    expect(extractHtmlCspMetas(html)).toEqual([
      { line: 1, value: "default-src 'self'" },
      { line: 2, value: 'img-src *' },
    ]);
  });

  it('returns nothing when there is no CSP meta', () => {
    expect(extractHtmlCspMetas('<html><head><meta charset="UTF-8"></head></html>')).toEqual([]);
  });
});
