/**
 * Small JSON-over-HTTP helper with a hard timeout. Uses the global fetch that
 * ships with Node 18+, so no extra dependency is needed.
 */
export async function fetchJson<T = any>(
  url: string,
  init: { headers?: Record<string, string>; timeoutMs: number },
): Promise<T> {
  const res = await fetch(url, {
    method: 'GET',
    headers: { Accept: 'application/json', ...(init.headers || {}) },
    signal: AbortSignal.timeout(init.timeoutMs),
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  }
  return (await res.json()) as T;
}

export async function fetchText(url: string, timeoutMs: number): Promise<string> {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  }
  return res.text();
}
