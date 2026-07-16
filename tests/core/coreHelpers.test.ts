import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseUrl, isLocalhostHost } from '../../src/core/url.js';
import { readElectronVersion } from '../../src/core/electronVersion.js';

describe('parseUrl', () => {
  it('reads scheme and host from an http(s) URL', () => {
    expect(parseUrl('http://example.com/app')).toEqual({ scheme: 'http', host: 'example.com' });
    expect(parseUrl('https://example.com')).toEqual({ scheme: 'https', host: 'example.com' });
  });

  it('strips userinfo and port to get the real host', () => {
    expect(parseUrl('https://user:pass@example.com:8443/x').host).toBe('example.com');
    // host is whatever the connection actually targets — userinfo before @ is not the host
    expect(parseUrl('http://localhost@evil.com/').host).toBe('evil.com');
  });

  it('handles an IPv6 literal host', () => {
    expect(parseUrl('http://[::1]:3000/').host).toBe('::1');
  });

  it('returns a scheme but no host for authority-less URLs', () => {
    expect(parseUrl('file:///etc/passwd')).toMatchObject({ scheme: 'file' });
    expect(parseUrl('file:///etc/passwd').host).toBeFalsy();
    expect(parseUrl('mailto:foo@bar.com')).toEqual({ scheme: 'mailto' });
  });
});

describe('isLocalhostHost', () => {
  it('recognizes loopback hosts', () => {
    for (const h of ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'app.localhost']) {
      expect(isLocalhostHost(h)).toBe(true);
    }
  });

  it('does not treat a lookalike remote host as localhost', () => {
    expect(isLocalhostHost('localhost.evil.com')).toBe(false);
    expect(isLocalhostHost('example.com')).toBe(false);
    expect(isLocalhostHost(undefined)).toBe(false);
  });
});

describe('readElectronVersion', () => {
  let scratch: string | undefined;
  afterEach(() => {
    if (scratch) {
      fs.rmSync(scratch, { recursive: true, force: true });
      scratch = undefined;
    }
  });

  function withPackageJson(pkg: unknown): string {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ea-ver-'));
    fs.writeFileSync(path.join(scratch, 'package.json'), JSON.stringify(pkg));
    return scratch;
  }

  it('parses the major from common range forms in dev/deps', () => {
    expect(readElectronVersion(withPackageJson({ devDependencies: { electron: '^43.1.0' } }))).toBe(43);
    expect(readElectronVersion(withPackageJson({ devDependencies: { electron: '~12.0.0' } }))).toBe(12);
    expect(readElectronVersion(withPackageJson({ dependencies: { electron: '>=20.0.0' } }))).toBe(20);
    expect(readElectronVersion(withPackageJson({ devDependencies: { electron: '11' } }))).toBe(11);
  });

  it('returns undefined for unparseable ranges or a missing dependency', () => {
    expect(readElectronVersion(withPackageJson({ devDependencies: { electron: '*' } }))).toBeUndefined();
    expect(readElectronVersion(withPackageJson({ devDependencies: { electron: 'latest' } }))).toBeUndefined();
    expect(readElectronVersion(withPackageJson({ devDependencies: {} }))).toBeUndefined();
  });

  it('returns undefined when there is no package.json', () => {
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ea-ver-'));
    expect(readElectronVersion(scratch)).toBeUndefined();
  });
});
