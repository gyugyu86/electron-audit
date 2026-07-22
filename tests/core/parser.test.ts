import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseSource } from '../../src/core/parser.js';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA020 } from '../../src/core/rules/EA020.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

// `.ts` (no JSX) vs `.tsx` (JSX) is a TypeScript language rule. The parser
// must pick the jsx plugin by extension, or a `.ts` generic (`<T>`) is read as
// JSX and the file is silently skipped.
describe('parseSource: extension-aware jsx plugin', () => {
  const GENERIC_TS = 'const id = <T>(x: T): T => x;\nexport default id;\n';
  const JSX = 'export const C = () => <div className="x">hi</div>;\n';

  it('parses a .ts generic arrow (jsx off for .ts, so `<T>` is a type param)', () => {
    expect(parseSource(GENERIC_TS, '/x/a.ts')).toBeDefined();
  });

  it('leaves the same source ambiguous under .tsx (documents why the split matters)', () => {
    // Under `.tsx`, `<T>(...)` collides with a JSX open tag and must be written
    // `<T,>`; the bare form only parses as `.ts`. This is the exact case the
    // extension split fixes.
    expect(parseSource(GENERIC_TS, '/x/a.tsx')).toBeUndefined();
  });

  it('still parses JSX in a .tsx file (no regression)', () => {
    expect(parseSource(JSX, '/x/c.tsx')).toBeDefined();
  });

  it('still parses JSX in a .js file (React convention kept)', () => {
    expect(parseSource(JSX, '/x/c.js')).toBeDefined();
  });
});

describe('a .ts file with generics is analyzed, not silently skipped', () => {
  it('catches an EA020 exec injection the jsx-on parser used to miss', () => {
    const scan = scanProject({ rootDir: path.join(FIXTURES, 'parser-ts-generic') });
    const result = new RuleEngine([EA020]).run(scan.files);
    expect(result.filesUnparsable).toBe(0); // the .ts parses now
    expect(result.findings.some((finding) => finding.ruleId === 'EA020')).toBe(true);
  });
});
