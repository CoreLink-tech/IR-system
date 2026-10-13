/**
 * Runtime settings. The deployed dashboard reads /config.json when it starts, so the same
 * build can be pointed at any API without rebuilding. Nothing in it is secret.
 */
export interface AppConfig { apiBaseUrl: string; idleTimeoutMinutes: number }

const fromEnv: AppConfig = {
  apiBaseUrl: (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, ''),
  idleTimeoutMinutes: Number(import.meta.env.VITE_IDLE_TIMEOUT_MINUTES ?? 30) || 30,
};

let current: AppConfig = { ...fromEnv };

export const config = (): AppConfig => current;
export const setConfig = (c: Partial<AppConfig>) => {
  current = { ...current, ...c, apiBaseUrl: (c.apiBaseUrl ?? current.apiBaseUrl).replace(/\/+$/, '') };
};

export async function loadConfig(): Promise<void> {
  try {
    const res = await fetch('/config.json', { cache: 'no-store' });
    if (!res.ok) return;
    const j = await res.json();
    setConfig({
      ...(typeof j.apiBaseUrl === 'string' ? { apiBaseUrl: j.apiBaseUrl } : {}),
      ...(Number(j.idleTimeoutMinutes) > 0 ? { idleTimeoutMinutes: Number(j.idleTimeoutMinutes) } : {}),
    });
  } catch { /* keep the defaults */ }
}
