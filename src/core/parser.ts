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

// Target projects are arbitrary and may contain files that don't parse
// (partial edits, non-JS/TS content with a matching extension, etc.) —
// callers treat `undefined` as "skip this file", not a crash.
export function parseSource(content: string, filePath: string): ParsedFile | undefined {
  const plugins: ParserPlugin[] = TS_NO_JSX_EXTENSIONS.has(path.extname(filePath).toLowerCase())
    ? ['typescript']
    : ['typescript', 'jsx'];
  try {
    const ast = parse(content, {
      sourceType: 'unambiguous',
      plugins,
      sourceFilename: filePath,
    });
    return { ast };
  } catch {
    return undefined;
  }
}
