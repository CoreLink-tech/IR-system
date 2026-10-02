import { Logger } from '@nestjs/common';
import { fetchText } from './http.util';
import { IpIntelProvider, PartialIntel } from './provider.types';

const DEFAULT_LIST_URL = 'https://check.torproject.org/torbulkexitlist';
const REFRESH_MS = 6 * 60 * 60 * 1000;

/**
 * Detects Tor exit nodes using the public bulk exit list published by the Tor
 * Project. The list is downloaded once and refreshed in the background, so a
 * lookup is an in-memory set check with no per-request network call.
 * Free, keyless, and the most reliable Tor signal available.
 */
export class TorExitProvider implements IpIntelProvider {
  readonly name = 'tor';
  private readonly logger = new Logger('TorExitProvider');
  private exits = new Set<string>();
  private loadedAt = 0;
  private loading: Promise<void> | null = null;

  constructor(
    private readonly timeoutMs: number,
    private readonly listUrl: string = process.env.TOR_EXIT_LIST_URL || DEFAULT_LIST_URL,
  ) {}

  async lookup(ip: string): Promise<PartialIntel | null> {
    await this.ensureLoaded();
    if (this.exits.has(ip)) {
      return { isTor: true, isProxy: true };
    }
    return {};
  }

  private async ensureLoaded(): Promise<void> {
    const fresh = this.loadedAt > 0 && Date.now() - this.loadedAt < REFRESH_MS;
    if (fresh) return;
    if (!this.loading) {
      this.loading = this.refresh().finally(() => { this.loading = null; });
    }
    // If we already hold an older list, keep serving it while a refresh runs.
    if (this.loadedAt > 0) return;
    await this.loading;
  }

  private async refresh(): Promise<void> {
    try {
      const body = await fetchText(this.listUrl, Math.max(this.timeoutMs, 10000));
      const next = new Set(
        body.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')),
      );
      if (next.size === 0) throw new Error('Tor exit list was empty');
      this.exits = next;
      this.loadedAt = Date.now();
      this.logger.log(`Loaded ${next.size} Tor exit nodes`);
    } catch (err) {
      this.logger.warn(`Tor exit list refresh failed: ${(err as Error).message}`);
      // Keep any previously loaded list. With no list at all, surface the failure.
      if (this.loadedAt === 0) throw err;
    }
  }
}
