// `.mts` is TypeScript with JSX disabled, exactly like `.ts`: the `<T>` below
// is a type parameter, never a JSX open tag. parser.ts has always listed
// `.mts` in TS_NO_JSX_EXTENSIONS, but the scanner never handed it a `.mts`
// file, so that branch was unreachable end to end. This fixture makes it live:
// with the jsx plugin on, `<T>` fails to parse, the whole file is skipped, and
// the execSync below disappears from the report.
import { execSync } from 'node:child_process';

const first = <T>(values: T[]): T => values[0];

export function build(configs: string[]): void {
  // EA020
  execSync(`electron-builder --config ${first(configs)}`);
}
