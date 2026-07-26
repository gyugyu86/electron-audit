import { parse, type ParserPlugin } from '@babel/parser';
import path from 'node:path';
import type { File } from '@babel/types';

export interface ParsedFile {
  ast: File;
}

// TypeScript's `.ts` (JSX not allowed) vs `.tsx` (JSX allowed) is a language
// rule, not a heuristic. In a `.ts` file `<T>` is always a type/generic, never
// a JSX open tag — so enabling the jsx plugin there makes valid `.ts` generics
// (`function f<T>()`, `const g = <T>(x: T) => x`) fail to parse; the `<` is
// read as JSX and the whole file is silently skipped, a quiet false negative.
// Pick the plugin set by extension: `.ts`/`.mts`/`.cts` get typescript only;
// everything else keeps jsx. `.js`/`.jsx`/`.tsx` deliberately keep jsx —
// `.tsx` requires it, and React projects put JSX in plain `.js` files, so
// turning it off there would break real code the opposite way.
const TS_NO_JSX_EXTENSIONS = new Set(['.ts', '.mts', '.cts']);

// Decorators can't be handled the same way. The two dialects are mutually
// exclusive in @babel/parser ("Cannot use the decorators and decorators-legacy
// plugin together"), neither is a superset of the other, and — unlike JSX —
// both live in plain `.ts`, so no extension can choose between them:
//   - only `decorators-legacy` parses parameter decorators
//     (`constructor(@Inject() private x)`), the Angular/NestJS/TypeORM DI shape;
//   - only the standard `decorators` parses a decorator placed after `export`
//     (`export @dec class`).
// Committing to one would leave the other dialect's files unparsed — skipped
// whole, with every rule blind to them. So both are tried, in order.
//
// ORDER — legacy first. Measured across real Electron apps: the projects that
// use decorators at all compile with `experimentalDecorators` (legacy
// semantics), and parameter decorators are legacy-only, so legacy succeeds far
// more often and trying it first minimizes retries. Order does not change
// RESULTS today, and that is a load-bearing assumption worth stating: it holds
// only because no rule inspects Decorator nodes — the two dialects differ in
// how they shape those nodes, not in the call/import/class nodes rules read.
// If a future rule ever reads decorators (an IPC or framework-specific rule is
// the plausible case), that assumption breaks and this order becomes a silent
// behavior switch — revisit it deliberately at that point.
//
// `decoratorAutoAccessors` rides along with both dialects: `@dec accessor x`
// needs it in ADDITION to a decorator plugin, and it composes with either one
// without changing anything else.
const DECORATOR_FALLBACKS: readonly ParserPlugin[][] = [
  ['decorators-legacy', 'decoratorAutoAccessors'],
  ['decorators', 'decoratorAutoAccessors'],
];

// `decoratorAutoAccessors` belongs in this set, not just in the fallback plugin
// lists above. A file whose only unsupported syntax is a bare `accessor x = 1`
// — no decorator anywhere — fails with `missingPlugin: ["decoratorAutoAccessors"]`
// on its own (measured), so without that name here the gate would not fire and
// the file would be skipped whole. Removing it silently drops those files, which
// is why a test asserts the bare-accessor case specifically.
const DECORATOR_PLUGIN_NAMES = new Set(['decorators', 'decorators-legacy', 'decoratorAutoAccessors']);

// The retry is gated to failures that are ACTUALLY a missing decorator plugin.
// @babel/parser reports that structurally on the error (`missingPlugin`), so
// this does not depend on the wording of an error message. Everything else
// fails once and stays failed: an ordinary syntax error, binary content behind
// a `.js` extension, or the RangeError a deeply-nested file throws (which
// carries no `missingPlugin` at all) cannot be fixed by another dialect, and
// retrying them would triple parse work on exactly the adversarial input this
// tool is built to survive.
//
// Note this checks the CONTENTS of `missingPlugin`, not merely that the field
// exists. Other unsupported proposals set it too — measured values include
// `["pipelineOperator"]`, `["doExpressions"]` and `["throwExpressions"]` — and
// no decorator dialect can parse those, so an existence check would spend two
// extra parses per file to fail anyway. Checking the names keeps the retry to
// the cases a retry can actually fix.
function needsDecoratorPlugin(error: unknown): boolean {
  const missing = (error as { missingPlugin?: unknown } | null | undefined)?.missingPlugin;
  return (
    Array.isArray(missing) &&
    missing.some((name) => typeof name === 'string' && DECORATOR_PLUGIN_NAMES.has(name))
  );
}

// Target projects are arbitrary and may contain files that don't parse
// (partial edits, non-JS/TS content with a matching extension, etc.) —
// callers treat `undefined` as "skip this file", not a crash.
export function parseSource(content: string, filePath: string): ParsedFile | undefined {
  const base: ParserPlugin[] = TS_NO_JSX_EXTENSIONS.has(path.extname(filePath).toLowerCase())
    ? ['typescript']
    : ['typescript', 'jsx'];

  const attempt = (plugins: ParserPlugin[]): ParsedFile => ({
    ast: parse(content, { sourceType: 'unambiguous', plugins, sourceFilename: filePath }),
  });

  try {
    return attempt(base);
  } catch (error) {
    if (!needsDecoratorPlugin(error)) {
      return undefined;
    }
  }

  for (const dialect of DECORATOR_FALLBACKS) {
    try {
      return attempt([...base, ...dialect]);
    } catch {
      // Wrong dialect for this file — fall through to the next one.
    }
  }
  return undefined;
}
