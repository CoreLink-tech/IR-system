import { fetchJson } from './http.util';
import { IpIntelProvider, PartialIntel } from './provider.types';

/**
 * IPinfo adapter. Requires IPINFO_TOKEN. Geolocation is available on every
 * plan. The "privacy" block (vpn, proxy, tor, hosting) is only returned on
 * plans that include privacy detection, so each flag is read defensively and
 * simply stays unset when the plan does not provide it.
 */
export class IpInfoProvider implements IpIntelProvider {
  readonly name = 'ipinfo';

  constructor(
    private readonly timeoutMs: number,
    private readonly token: string | undefined = process.env.IPINFO_TOKEN,
  ) {
    if (!this.token) throw new Error('IPINFO_TOKEN is required for the ipinfo provider');
  }

  async lookup(ip: string): Promise<PartialIntel | null> {
    const url = `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(this.token!)}`;
    const data = await fetchJson<any>(url, { timeoutMs: this.timeoutMs });
    const out: PartialIntel = {
      country: data.country || undefined,
      region: data.region || undefined,
      city: data.city || undefined,
    };
    const privacy = data.privacy;
    if (privacy && typeof privacy === 'object') {
      if (typeof privacy.vpn === 'boolean') out.isVpn = privacy.vpn;
      if (typeof privacy.proxy === 'boolean') out.isProxy = privacy.proxy;
      if (typeof privacy.tor === 'boolean') out.isTor = privacy.tor;
      if (typeof privacy.hosting === 'boolean') out.isDatacenter = privacy.hosting;
    }
    return out;
  }
}
