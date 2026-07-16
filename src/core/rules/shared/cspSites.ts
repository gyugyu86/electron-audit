import traverse from '@babel/traverse';
import * as t from '@babel/types';
import type { NodePath } from '@babel/traverse';
import type { File } from '@babel/types';
import type { AggregateRuleContext } from '../../types.js';
import { resolveStaticStringValue } from '../../ast/resolveStaticString.js';
import { tokenizeCsp } from '../../csp/cspTokenizer.js';

export interface CspHeaderSite {
  line: number;
  // Statically-readable CSP header string(s) at this site. Empty when the
  // header is set but its value is dynamic (a variable/expression) — the
  // site still counts as "CSP is configured in JS" for EA010, but EA011/012/
  // 013 have nothing to tokenize.
  values: string[];
}

// Finds places in a file's JS/TS AST where a Content-Security-Policy response
// header is set — the ONLY CSP surface this tool sees. It does NOT see CSP in
// an HTML <meta http-equiv> tag (HTML is not parsed) or a value assembled
// dynamically; that scope limit is what makes EA010's absence check a
// heuristic. Recognized shapes:
//   - an object property  'Content-Security-Policy': [ "..." ]   (onHeadersReceived callback)
//   - a member assignment  headers['Content-Security-Policy'] = [ "..." ]
// The header name is matched case-insensitively.
const cache = new WeakMap<File, CspHeaderSite[]>();

export function findCspHeaderSites(ast: File): CspHeaderSite[] {
  const cached = cache.get(ast);
  if (cached) {
    return cached;
  }

  const sites: CspHeaderSite[] = [];

  traverse(ast, {
    ObjectProperty(path) {
      if (isCspStringKey(path.node.key)) {
        sites.push({ line: path.node.loc?.start.line ?? 0, values: readCspValues(path.node.value, path) });
      }
    },
    AssignmentExpression(path) {
      const left = path.node.left;
      if (t.isMemberExpression(left) && left.computed && isCspStringKey(left.property)) {
        sites.push({ line: path.node.loc?.start.line ?? 0, values: readCspValues(path.node.right, path) });
      }
    },
  });

  cache.set(ast, sites);
  return sites;
}

function isCspStringKey(node: t.Node): boolean {
  return t.isStringLiteral(node) && node.value.toLowerCase() === 'content-security-policy';
}

function readCspValues(valueNode: t.Node, path: NodePath): string[] {
  // Electron's header form is an array of strings; also accept a bare string.
  if (t.isArrayExpression(valueNode)) {
    const out: string[] = [];
    for (const element of valueNode.elements) {
      if (element && t.isExpression(element)) {
        const resolved = resolveStaticStringValue(element, path);
        if (resolved !== undefined) {
          out.push(resolved);
        }
      }
    }
    return out;
  }

  const resolved = resolveStaticStringValue(valueNode, path);
  return resolved !== undefined ? [resolved] : [];
}

// ── Unified CSP surface (JS response headers + HTML <meta>) ────────────────

export interface CspString {
  file: string;
  line: number;
  value: string;
}

// Every statically-readable CSP string across the project: JS response-header
// sites in each parsed file, PLUS HTML <meta http-equiv> tags gathered by the
// scanner. EA011/EA012 judge this list — the SOURCE is broadened from JS to
// HTML while the tokenizer and per-directive judgment stay 100% shared.
export function collectCspStrings(context: AggregateRuleContext): CspString[] {
  const out: CspString[] = [];
  for (const pf of context.parsedFiles) {
    for (const site of findCspHeaderSites(pf.ast)) {
      for (const value of site.values) {
        out.push({ file: pf.file.path, line: site.line, value });
      }
    }
  }
  for (const meta of context.project.htmlCspSites ?? []) {
    out.push({ file: meta.file, line: meta.line, value: meta.value });
  }
  return out;
}

// Is a CSP configured ANYWHERE (JS site or HTML <meta>), even with a dynamic/
// unreadable value? Used by EA010's absence check — a JS site with an empty
// values[] still counts as "configured".
export function hasAnyCspConfigured(context: AggregateRuleContext): boolean {
  const inJs = context.parsedFiles.some((pf) => findCspHeaderSites(pf.ast).length > 0);
  const inHtml = (context.project.htmlCspSites ?? []).length > 0;
  return inJs || inHtml;
}

// ── Per-directive judgment (shared by EA011/EA012) ─────────────────────────

// Directives where an inline source means inline SCRIPT execution — the
// XSS→RCE path. `unsafe-inline` here is high severity. Everywhere else
// (style-src, img-src, ...) inline is a limited attack surface and normal
// apps use it (Tailwind, styled-components), so it's medium.
const SCRIPT_EXEC_DIRECTIVES = new Set(['default-src', 'script-src', 'script-src-elem', 'script-src-attr']);

export interface UnsafeCspHit {
  directive: string;
  // Directive-graded: 'unsafe-eval' is always high (eval execution is always
  // dangerous); 'unsafe-inline' is high in a script-execution directive,
  // medium otherwise.
  severity: 'high' | 'medium';
  keywords: string[];
}

// Directives whose sources include 'unsafe-inline' / 'unsafe-eval', split by
// graded severity. Token-based (never a raw substring scan); keyword
// comparison is case-insensitive but the original token case/order is kept
// for the finding message.
export function findUnsafeCspHits(cspValue: string): UnsafeCspHit[] {
  const hits: UnsafeCspHit[] = [];
  for (const directive of tokenizeCsp(cspValue)) {
    const high: string[] = [];
    const medium: string[] = [];
    for (const source of directive.sources) {
      const keyword = source.toLowerCase();
      if (keyword === "'unsafe-eval'") {
        high.push(source);
      } else if (keyword === "'unsafe-inline'") {
        (SCRIPT_EXEC_DIRECTIVES.has(directive.name) ? high : medium).push(source);
      }
    }
    if (high.length > 0) {
      hits.push({ directive: directive.name, severity: 'high', keywords: high });
    }
    if (medium.length > 0) {
      hits.push({ directive: directive.name, severity: 'medium', keywords: medium });
    }
  }
  return hits;
}

// Directive names whose sources include an EXACT "*" token (all origins). A
// partial wildcard like "*.foo.com" is intentionally excluded.
export function findWildcardCspDirectives(cspValue: string): string[] {
  return tokenizeCsp(cspValue)
    .filter((directive) => directive.sources.includes('*'))
    .map((directive) => directive.name);
}
