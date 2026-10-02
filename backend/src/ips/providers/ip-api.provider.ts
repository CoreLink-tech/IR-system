import { fetchJson } from './http.util';
import { IpIntelProvider, PartialIntel } from './provider.types';

/**
 * ip-api.com adapter. The free tier needs no key but is HTTP only and limited
 * to roughly 45 requests per minute for non-commercial use. Set IP_API_KEY to
 * use the paid HTTPS endpoint (pro.ip-api.com).
 *
 * The API reports a single "proxy" flag that covers proxies, VPNs and Tor
 * without distinguishing them, so it maps to isProxy only. The "hosting" flag
 * maps to isDatacenter.
 */
export class IpApiProvider implements IpIntelProvider {
  readonly name = 'ipapi';

  constructor(
    private readonly timeoutMs: number,
    private readonly apiKey: string | undefined = process.env.IP_API_KEY,
  ) {}

  async lookup(ip: string): Promise<PartialIntel | null> {
    const fields = 'status,message,country,regionName,city,proxy,hosting';
    const base = this.apiKey ? 'https://pro.ip-api.com/json' : 'http://ip-api.com/json';
    const url =
      `${base}/${encodeURIComponent(ip)}?fields=${fields}` +
      (this.apiKey ? `&key=${encodeURIComponent(this.apiKey)}` : '');
    const data = await fetchJson<any>(url, { timeoutMs: this.timeoutMs });
    if (data.status !== 'success') {
      throw new Error(`ip-api: ${data.message || 'lookup failed'}`);
    }
    return {
      country: data.country || undefined,
      region: data.regionName || undefined,
      city: data.city || undefined,
      isProxy: data.proxy === true,
      isDatacenter: data.hosting === true,
    };
  }
}
