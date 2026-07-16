import { describe, expect, it } from 'vitest';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import { parseSource } from '../../src/core/parser.js';
import { isStaticSafeLiteral } from '../../src/core/ast/isStaticSafeLiteral.js';

// Evaluates isStaticSafeLiteral on the first argument of a `probe(...)` call
// found in `source`, so each case below reads as plain, realistic code.
function evaluateFirstProbeArg(source: string): boolean {
  const parsed = parseSource(source, 'virtual.js');
  if (!parsed) {
    throw new Error('fixture source failed to parse');
  }

  let result: boolean | undefined;
  traverse(parsed.ast, {
    CallExpression(path) {
      if (result !== undefined) return;
      if (!t.isIdentifier(path.node.callee) || path.node.callee.name !== 'probe') return;
      const arg = path.node.arguments[0];
      if (!arg) return;
      result = isStaticSafeLiteral(arg, path);
    },
  });

  if (result === undefined) {
    throw new Error('no probe(...) call found in fixture source');
  }
  return result;
}

describe('isStaticSafeLiteral', () => {
  it('string/number/boolean literals are safe', () => {
    expect(evaluateFirstProbeArg(`probe('hello');`)).toBe(true);
    expect(evaluateFirstProbeArg(`probe(42);`)).toBe(true);
    expect(evaluateFirstProbeArg(`probe(true);`)).toBe(true);
  });

  it('a same-file const bound to a literal folds safe', () => {
    expect(evaluateFirstProbeArg(`const CMD = 'ls'; probe(CMD);`)).toBe(true);
  });

  it('a chain of consts folds safe', () => {
    expect(evaluateFirstProbeArg(`const A = 'ls'; const B = A; probe(B);`)).toBe(true);
  });

  it('a let binding does not fold, even with a literal initializer', () => {
    expect(evaluateFirstProbeArg(`let cmd = 'ls'; probe(cmd);`)).toBe(false);
  });

  it('a var binding does not fold', () => {
    expect(evaluateFirstProbeArg(`var cmd = 'ls'; probe(cmd);`)).toBe(false);
  });

  it('a function parameter is not safe', () => {
    expect(evaluateFirstProbeArg(`function run(cmd) { probe(cmd); }`)).toBe(false);
  });

  it('process.env.X (a member expression) is not safe', () => {
    expect(evaluateFirstProbeArg(`probe(process.env.CMD);`)).toBe(false);
  });

  it('a function call result is not safe', () => {
    expect(evaluateFirstProbeArg(`probe(getCommand());`)).toBe(false);
  });

  it('an imported binding does not fold, even if it looks like a constant', () => {
    expect(evaluateFirstProbeArg(`import { CMD } from './config.js'; probe(CMD);`)).toBe(false);
  });

  it('a template literal built only from safe pieces is safe', () => {
    expect(evaluateFirstProbeArg(`const NAME = 'tmp'; probe(\`prefix-\${NAME}-suffix\`);`)).toBe(true);
  });

  it('a template literal with an unsafe interpolation is unsafe', () => {
    expect(evaluateFirstProbeArg(`function run(id) { probe(\`prefix-\${id}\`); }`)).toBe(false);
  });

  it('a "+" concatenation of only safe pieces is safe', () => {
    expect(evaluateFirstProbeArg(`const A = 'x'; const B = 'y'; probe(A + B);`)).toBe(true);
  });

  it('a "+" concatenation with an unsafe operand is unsafe', () => {
    expect(evaluateFirstProbeArg(`function run(id) { probe('x' + id); }`)).toBe(false);
  });
});
