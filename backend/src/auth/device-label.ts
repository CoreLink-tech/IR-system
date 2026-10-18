/**
 * A short, human label for the sessions page, such as "Chrome on Windows". It is only a label for the
 * owner to recognise their own devices; it is never used to decide anything.
 */
export function deviceLabel(userAgent?: string | null): string {
  const ua = String(userAgent ?? '').slice(0, 400);
  if (!ua) return 'Unknown device';
  const browser =
    /Edg(e|A|iOS)?\//.test(ua) ? 'Edge' :
    /OPR\/|Opera/.test(ua) ? 'Opera' :
    /Firefox\/|FxiOS\//.test(ua) ? 'Firefox' :
    /Chrome\/|CriOS\//.test(ua) ? 'Chrome' :
    /Safari\//.test(ua) && /Version\//.test(ua) ? 'Safari' :
    /^curl\//i.test(ua) ? 'curl' :
    /^PHP|SecurityClient/i.test(ua) ? 'Server script' :
    /node|axios|undici/i.test(ua) ? 'Script' : null;
  const os =
    /Windows/.test(ua) ? 'Windows' :
    /Android/.test(ua) ? 'Android' :
    /iPhone|iPad|iPod/.test(ua) ? 'iOS' :
    /Mac OS X|Macintosh/.test(ua) ? 'macOS' :
    /CrOS/.test(ua) ? 'ChromeOS' :
    /Linux|X11/.test(ua) ? 'Linux' : null;
  if (browser && os) return `${browser} on ${os}`;
  return browser ?? os ?? 'Unknown device';
}
