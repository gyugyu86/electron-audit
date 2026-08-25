import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scanProject } from '../../src/core/scanner.js';
import { RuleEngine } from '../../src/core/ruleEngine.js';
import { EA031 } from '../../src/core/rules/EA031.js';
import type { Finding } from '../../src/core/types.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(dirname, '../fixtures');

function run(fixture: string): Finding[] {
  const scan = scanProject({ rootDir: path.join(FIXTURES, 'EA031', fixture) });
  return new RuleEngine([EA031]).run(scan.files, scan.project).findings;
}

function lineContaining(fixture: string, needle: string): number {
  const source = readFileSync(path.join(FIXTURES, 'EA031', fixture, 'preload.js'), 'utf8').split('\n');
  return source.findIndex((line) => line.includes(needle)) + 1;
}

describe('EA031 contextBridge exposes a caller-chosen IPC channel', () => {
  // One assertion per forwarding method, pinned to the line its own exposed
  // function is written on. A total would go red for every method at once and
  // say nothing about which one the rule actually recognized.
  for (const method of ['send', 'invoke', 'sendSync', 'sendToHost', 'on', 'once']) {
    it(`reports a function forwarding its channel to ipcRenderer.${method}`, () => {
      const findings = run('vulnerable-channel-parameter');
      const atLine = findings.filter((f) => f.line === lineContaining('vulnerable-channel-parameter', `ipcRenderer.${method}(`));
      expect(atLine).toHaveLength(1);
      expect(atLine[0]).toMatchObject({ ruleId: 'EA031', severity: 'medium', confidence: 'high' });
      expect(atLine[0]?.target).toContain(`ipcRenderer.${method}`);
    });
  }

  // A deliberate miss, pinned so it cannot be undone by accident. Reading
  // const-held objects was measured: every case it reached already checked the
  // channel against an allowlist, so widening bought a false-positive class
  // and no true finding. Recognizing such a guard first — the way EA040 does
  // for schemes — is what would make the wider read safe.
  it('does not report a pass-through held in a const (a miss taken on purpose)', () => {
    expect(run('safe-const-object')).toHaveLength(0);
  });

  it('stays silent when the preload fixes every channel itself', () => {
    expect(run('safe-fixed-channels')).toHaveLength(0);
  });

  // The distinguishing case. A parameter reaching ipcRenderer is how any
  // bridge passes data; only a parameter landing in the CHANNEL position is
  // this rule's subject. Without this, the rule would flag every exposed
  // function that talks to ipcRenderer at all.
  it('stays silent when the parameter is the payload rather than the channel', () => {
    expect(run('safe-parameter-is-payload')).toHaveLength(0);
  });

  it('stays silent when the channel identifier is not a parameter of the exposed function', () => {
    expect(run('safe-channel-not-a-parameter')).toHaveLength(0);
  });

  it('stays silent when nothing is exposed across the bridge', () => {
    expect(run('safe-no-context-bridge')).toHaveLength(0);
  });

  // `exposeInMainWorld` only crosses the context boundary when it is
  // contextBridge's; the same method name on anything else exposes nothing.
  it('stays silent when the receiver of exposeInMainWorld is not contextBridge', () => {
    expect(run('safe-not-context-bridge-receiver')).toHaveLength(0);
  });

  // Reporting at high confidence means saying nothing about an API surface
  // that cannot be read — a deliberate miss rather than a guess.
  it('stays silent when the exposed object cannot be resolved statically', () => {
    expect(run('safe-unresolvable-api')).toHaveLength(0);
  });
});
