import { parse } from '@babel/parser';
import type { File } from '@babel/types';

export interface ParsedFile {
  ast: File;
}

// Target projects are arbitrary and may contain files that don't parse
// (partial edits, non-JS/TS content with a matching extension, etc.) —
// callers treat `undefined` as "skip this file", not a crash.
export function parseSource(content: string, filePath: string): ParsedFile | undefined {
  try {
    const ast = parse(content, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx'],
      sourceFilename: filePath,
    });
    return { ast };
  } catch {
    return undefined;
  }
}
