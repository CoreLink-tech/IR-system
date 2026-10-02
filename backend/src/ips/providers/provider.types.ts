/**
 * Contract for pluggable IP intelligence providers.
 *
 * A provider answers a single question: "what do you know about this IP?"
 * It may return only the fields it is able to determine. The intelligence
 * service merges partial answers from several providers into one result.
 *
 * reputationScore semantics: 0..100, where a HIGHER value means the address
 * is MORE likely to be abusive (this matches AbuseIPDB's confidence score).
 */
export interface IntelResult {
  country?: string;
  region?: string;
  city?: string;
  isVpn: boolean;
  isProxy: boolean;
  isTor: boolean;
  isDatacenter: boolean;
  isMalicious: boolean;
  reputationScore: number;
  /** Names of the providers that contributed to this result. */
  sources?: string[];
}

export type PartialIntel = Partial<Omit<IntelResult, 'sources'>>;

export interface IpIntelProvider {
  /** Short stable identifier, used in config and logs (for example "abuseipdb"). */
  readonly name: string;
  /**
   * Look up one public IP address. Must throw on transport or API errors so the
   * service can apply its failure handling. Return null if the provider has no
   * information about the address.
   */
  lookup(ip: string): Promise<PartialIntel | null>;
}

/** Dependency-injection token for the list of active providers. */
export const IP_INTEL_PROVIDERS = 'IP_INTEL_PROVIDERS';
