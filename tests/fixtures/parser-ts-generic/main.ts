import { exec } from 'child_process';

// A generic arrow function: `<T>` is a TypeScript type parameter, legal only
// in a .ts file. With the jsx plugin enabled (the old, extension-blind
// behavior) `<T` was read as a JSX open tag, this file failed to parse, and
// the whole file — including the exec() below — was silently skipped.
const identity = <T>(x: T): T => x;

export function run(userInput: string): void {
  // EA020: a non-static value interpolated into a shell command string.
  exec(`echo ${identity(userInput)}`);
}
