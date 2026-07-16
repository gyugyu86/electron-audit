export interface HtmlCspMeta {
  line: number;
  value: string;
}

// SHALLOW, regex-only extraction of the CSP string from
// <meta http-equiv="Content-Security-Policy" content="..."> tags. This is
// deliberately NOT a real HTML parse — no parse5, no dependency. The only
// reason CSP-in-HTML was previously missed is that this tool doesn't read
// HTML; this narrow extractor widens the SOURCE (JS → HTML) so the existing
// cspTokenizer + EA011/EA012 judgment applies, nothing more. Full HTML
// parsing (and <webview>, EA043) is a v2 concern.
//
// Handles: case-insensitive tag/attribute names, single- OR double-quoted
// attribute values, http-equiv/content in any order, and multiple <meta>
// tags. Known shallow limit: a single-quoted content value whose CSP also
// uses single quotes ('self') can't be delimited by regex alone — but CSP
// with quoted keywords is virtually always in a double-quoted content
// attribute (the common, and dnsChanger/quick-start, case), which works.

// A <meta ...> tag. CSP values never contain '>', so stopping at the first
// '>' is safe. Linear pattern (single negated class, no nested quantifier) —
// no ReDoS.
const META_TAG = /<meta\b[^>]*>/gi;
const IS_CSP_HTTP_EQUIV = /http-equiv\s*=\s*["']?\s*content-security-policy\s*["']?/i;
const CONTENT_DOUBLE = /content\s*=\s*"([^"]*)"/i;
const CONTENT_SINGLE = /content\s*=\s*'([^']*)'/i;

export function extractHtmlCspMetas(html: string): HtmlCspMeta[] {
  const results: HtmlCspMeta[] = [];

  for (const match of html.matchAll(META_TAG)) {
    const tag = match[0];
    if (!IS_CSP_HTTP_EQUIV.test(tag)) {
      continue;
    }
    const content = CONTENT_DOUBLE.exec(tag) ?? CONTENT_SINGLE.exec(tag);
    const value = content?.[1];
    if (value === undefined) {
      continue;
    }
    results.push({ line: lineNumberAt(html, match.index ?? 0), value });
  }

  return results;
}

function lineNumberAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) {
    if (text[i] === '\n') {
      line += 1;
    }
  }
  return line;
}
