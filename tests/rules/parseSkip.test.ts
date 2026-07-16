import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA001 } from '../../src/core/rules/EA001.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));

describe('RuleEngine parse-skip handling', () => {
  it('skips unparsable files without crashing, and still runs rules on the rest', () => {
    const scan = scanProject({ rootDir: path.join(dirname, '../fixtures/parse-skip') });
    const result = new RuleEngine([EA001]).run(scan.files);

    expect(result.filesScanned).toBe(2);
    expect(result.filesUnparsable).toBe(1);
    expect(result.findings).toHaveLength(1);
  });
});
