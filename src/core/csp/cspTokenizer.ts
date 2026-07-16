export interface CspDirective {
  name: string;
  sources: string[];
}

// Primitive only: tokenizes a CSP header string into directives (split on
// `;`) then sources (split on whitespace within each directive). Wildcard
// judgments must operate on these tokens, not a raw `*` regex against the
// whole header — otherwise a partial wildcard like `*.foo.com` false-
// positives as a bare `*` source.
//
// The directive NAME is lowercased (CSP directive names are case-
// insensitive: `default-src` === `Default-Src`). Source tokens are kept in
// their ORIGINAL case, because hosts and schemes are case-sensitive in
// practice; consumers that match source KEYWORDS (`unsafe-inline`, `gap:`)
// do their own case-insensitive comparison.
//
// Rule-level judgments that use this tokenizer's output — EA010 (CSP
// absence, an AggregateRule) and EA013 (Cordova-leftover CSP signature) —
// live in src/core/rules/, not here. This directory holds the tokenizer
// primitive only.
//
// Robust by construction (no throw): an empty string, a string of only
// semicolons/whitespace, duplicate directives, and leading/trailing
// whitespace all yield a well-formed result. Duplicate directives are kept
// as separate entries (the tool reports on each rather than silently
// merging).
export function tokenizeCsp(header: string): CspDirective[] {
  const directives: CspDirective[] = [];

  for (const chunk of header.split(';')) {
    const trimmed = chunk.trim();
    if (trimmed === '') {
      continue;
    }
    const parts = trimmed.split(/\s+/);
    const name = parts[0]?.toLowerCase() ?? '';
    directives.push({ name, sources: parts.slice(1) });
  }

  return directives;
}
