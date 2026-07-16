import type { Finding } from './types.js';

export interface Report {
  findings: Finding[];
}

// Wraps a Finding[] into the format-agnostic result the CLI formatters
// (terminal/json/markdown) render. No formatting decisions happen here.
export function buildReport(findings: Finding[]): Report {
  return { findings };
}
