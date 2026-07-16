import type { File } from '@babel/types';
import { extractWebPreferences, type BrowserWindowCallSite } from '../../ast/webPreferencesExtractor.js';

// Consumer-side memoization of the webPreferences extractor, keyed by AST.
// EA002/003/004/005 (per-file) and EA006/EA041 (aggregate) all need the same
// per-window model for a given file within one RuleEngine run; this walks
// each AST once instead of once per rule. Kept out of the extractor itself
// so the extractor stays a pure, side-effect-free primitive.
const cache = new WeakMap<File, BrowserWindowCallSite[]>();

export function getWindowCallSites(ast: File, filePath: string): BrowserWindowCallSite[] {
  const cached = cache.get(ast);
  if (cached) {
    return cached;
  }
  const sites = extractWebPreferences(ast, filePath);
  cache.set(ast, sites);
  return sites;
}
