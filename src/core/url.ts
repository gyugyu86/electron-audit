export interface ParsedUrl {
  scheme?: string; // lowercased, without the trailing ':'
  host?: string; // lowercased host, without userinfo or port
}

const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);

// Deliberately minimal URL parsing (no WHATWG URL, which throws on the
// odd inputs static analysis sees) — just enough to read a scheme and, for
// scheme://authority forms, a host.
export function parseUrl(raw: string): ParsedUrl {
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(raw);
  const scheme = schemeMatch ? schemeMatch[1]?.toLowerCase() : undefined;

  const authorityMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#]*)/.exec(raw);
  if (!authorityMatch) {
    return { scheme };
  }

  const authority = authorityMatch[1] ?? '';
  const afterUserInfo = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
  // Strip a :port, but not the ':' inside an IPv6 literal like [::1].
  const host = afterUserInfo.startsWith('[')
    ? afterUserInfo.slice(1, afterUserInfo.indexOf(']') === -1 ? undefined : afterUserInfo.indexOf(']'))
    : afterUserInfo.split(':')[0];

  return { scheme, host: host?.toLowerCase() };
}

export function isLocalhostHost(host: string | undefined): boolean {
  if (!host) {
    return false;
  }
  return LOCALHOST_HOSTS.has(host) || host.endsWith('.localhost');
}
