import { IncidentFacts } from './report.types';
import { describeSpan, joinList, plural } from './language';

/**
 * Plain-English wording for each detection rule.
 *
 * Rules for writing narratives:
 *  - Any sentence that states a number, time or address takes it from IncidentFacts.
 *  - "why" text is general background about the type of attack. It makes no claim
 *    about this specific incident.
 *  - Never state something the facts do not support. When a count is zero or a
 *    signal is unknown, say less rather than guess.
 */
export interface Narrative {
  /** Short plain name for the kind of activity. */
  title: string;
  headline(f: IncidentFacts): string;
  what(f: IncidentFacts): string;
  why: string;
  actions(f: IncidentFacts): string[];
}

const ip = (f: IncidentFacts) => f.incident.sourceIp ?? 'an unidentified address';
const span = (f: IncidentFacts) => describeSpan(f.activity.firstEventAt, f.activity.lastEventAt);

/** Events on which a given rule fired, falling back to a total when unknown. */
function firedCount(f: IncidentFacts, code: string): number | null {
  const r = f.activity.rulesFired.find((x) => x.code === code);
  return r ? r.events : null;
}

/** Shared sentence about whether any login from this address succeeded. */
function loginOutcome(f: IncidentFacts): string {
  if (!f.signals.loginSuccessReported) return '';
  const n = f.activity.successfulLogins;
  if (n === 0) return ' No successful logins from this address were recorded in the same period.';
  return ` ${plural(n, 'successful login')} from this address ${n === 1 ? 'was' : 'were'} also recorded, so at least one account may have been accessed.`;
}

const reviewSuccessfulLogins = (f: IncidentFacts): string[] =>
  f.signals.loginSuccessReported && f.activity.successfulLogins > 0
    ? ['Review the accounts that logged in from this address and reset their passwords if the access was not expected.']
    : [];

export const NARRATIVES: Record<string, Narrative> = {
  brute_force_login: {
    title: 'Repeated failed logins',
    headline: (f) => `Repeated failed logins from ${ip(f)}`,
    what: (f) => {
      const a = f.activity;
      let s = `${plural(a.failedLogins, 'failed login attempt')} ${a.failedLogins === 1 ? 'was' : 'were'} recorded from ${ip(f)} ${span(f)}.`;
      if (a.distinctUsersFailed > 1) s += ` The attempts targeted ${a.distinctUsersFailed} different accounts.`;
      else if (a.distinctUsersFailed === 1) s += ' All of the attempts targeted the same account.';
      return s + loginOutcome(f);
    },
    why: 'Many failed logins in a short time is how password guessing looks. If one guess is correct, the attacker gets into a real account.',
    actions: (f) => [
      ...reviewSuccessfulLogins(f),
      'Keep the source address blocked while the activity continues.',
      'If the targeted accounts belong to staff or administrators, ask those people to confirm their passwords are strong and unique.',
    ],
  },

  credential_stuffing: {
    title: 'Login attempts across many accounts',
    headline: (f) => `Login attempts against many accounts from ${ip(f)}`,
    what: (f) => {
      const a = f.activity;
      return `${plural(a.failedLogins, 'failed login attempt')} from ${ip(f)} ${span(f)} were spread across ${a.distinctUsersFailed} different accounts.` + loginOutcome(f);
    },
    why: 'Trying a few passwords on many accounts is typical of attackers using lists of stolen usernames and passwords from other websites. It succeeds when customers reuse passwords.',
    actions: (f) => [
      ...reviewSuccessfulLogins(f),
      'Keep the source address blocked while the activity continues.',
      'Consider asking affected customers to change their passwords if any of these accounts show a successful login.',
      'Consider adding two-step verification or a CAPTCHA on the login page.',
    ],
  },

  high_request_rate: {
    title: 'Unusually high activity',
    headline: (f) => `Unusually high activity from ${ip(f)}`,
    what: (f) =>
      `${plural(f.activity.totalEvents, 'event')} ${f.activity.totalEvents === 1 ? 'was' : 'were'} recorded from ${ip(f)} ${span(f)}, which went over the alert limit for a single address.`,
    why: 'Very high request volume from one address can be an automated tool scanning the site, scraping data, or trying to overload it.',
    actions: () => [
      'Check whether this address belongs to a partner, a monitoring service or a legitimate integration before blocking it for long.',
      'If it is not expected, keep the source address blocked.',
    ],
  },

  user_enumeration: {
    title: 'Probing for valid accounts',
    headline: (f) => `Probing for valid accounts from ${ip(f)}`,
    what: (f) => {
      const a = f.activity;
      const parts: string[] = [];
      if (a.failedLogins) parts.push(plural(a.failedLogins, 'failed login'));
      if (a.passwordResets) parts.push(plural(a.passwordResets, 'password reset request'));
      return `${ip(f)} produced ${joinList(parts) || 'account-related activity'} ${span(f)}, touching ${a.distinctUsersFailed} different accounts.`;
    },
    why: 'Attackers test which usernames or email addresses exist so they can focus later attacks on real accounts.',
    actions: () => [
      'Make sure the login and password reset pages give the same response whether or not an account exists.',
      'Keep the source address blocked while the activity continues.',
    ],
  },

  password_reset_abuse: {
    title: 'Repeated password reset requests',
    headline: (f) => `Repeated password reset requests from ${ip(f)}`,
    what: (f) =>
      `${plural(f.activity.passwordResets, 'password reset request')} came from ${ip(f)} ${span(f)}, more than the alert limit.`,
    why: 'Repeated resets can be used to flood customers with emails, to take over accounts, or to find out which accounts exist.',
    actions: () => [
      'Check whether affected customers received a flood of reset emails and tell them not to click links they did not request.',
      'Consider limiting how many reset requests one address or account can make.',
    ],
  },

  suspicious_admin_access: {
    title: 'Administrative access from an untrusted network',
    headline: (f) => `Administrative access from an untrusted network (${ip(f)})`,
    what: (f) => {
      const net = f.ip?.isTor ? 'the Tor anonymizing network' : f.ip?.isMalicious ? 'an address listed as malicious' : 'an untrusted network';
      return `${plural(f.activity.adminAccesses, 'access')} to administrative areas of the site came from ${ip(f)} ${span(f)}. This address is part of ${net}.`;
    },
    why: 'Administrative areas control the whole site. Access from anonymizing or known-malicious networks is rarely legitimate.',
    actions: () => [
      'Confirm with your administrators whether they were using this connection. If not, treat it as a break-in attempt.',
      'Restrict administrative areas to known addresses or require two-step verification.',
    ],
  },

  known_malicious_ip: {
    title: 'Address with a bad reputation',
    headline: (f) => `Activity from a known malicious address (${ip(f)})`,
    what: (f) => {
      const rep = f.ip?.intelligenceChecked ? ` It has a reputation score of ${f.ip.reputationScore} out of 100, where higher means more abuse reported.` : '';
      return `${ip(f)} is listed as malicious by the IP reputation provider and was active ${span(f)}.${rep}`;
    },
    why: 'Addresses on reputation lists have been reported by other sites for attacks such as scanning, spam or break-in attempts.',
    actions: () => ['Keep the source address blocked.', 'Review what this address requested (see the technical report).'],
  },

  tor_or_proxy: {
    title: 'Anonymized connection',
    headline: (f) => `Activity from an anonymized connection (${ip(f)})`,
    what: (f) => {
      const kinds: string[] = [];
      if (f.ip?.isTor) kinds.push('the Tor network');
      if (f.ip?.isProxy) kinds.push('a proxy');
      if (f.ip?.isVpn) kinds.push('a VPN');
      return `Activity ${span(f)} came from ${ip(f)}, which is connected through ${joinList(kinds) || 'an anonymizing service'}. Using privacy tools is not an attack by itself, so this counts only as a contributing signal.`;
    },
    why: 'Attackers often hide behind anonymizing services, but so do many ordinary people who value privacy.',
    actions: () => ['Look at what else this address did. Act on the behavior, not only on the use of a privacy tool.'],
  },

  suspicious_payload: {
    title: 'Requests resembling hacking attempts',
    headline: (f) => `Requests resembling hacking attempts from ${ip(f)}`,
    what: (f) => {
      const n = firedCount(f, 'suspicious_payload');
      const count = n !== null ? plural(n, 'request') : 'At least one request';
      return `${count} from ${ip(f)} ${span(f)} contained text patterns commonly used to attack websites, such as script injection or database or file-path manipulation.`;
    },
    why: 'These patterns are used to try to steal data, take over pages shown to other visitors, or read files the site should not expose.',
    actions: () => [
      'Ask your developers to confirm the affected pages sanitize their input. The technical report lists the pages that were targeted.',
      'Keep the source address blocked while the activity continues.',
    ],
  },

  order_id_enumeration: {
    title: 'Systematic browsing of orders or products',
    headline: (f) => `Systematic browsing of orders or products by ${ip(f)}`,
    what: (f) => {
      const n = firedCount(f, 'order_id_enumeration');
      const count = n !== null ? plural(n, 'request') : 'A series of requests';
      return `${count} from ${ip(f)} ${span(f)} stepped through order, product or item pages one after another.`;
    },
    why: 'Stepping through numbered pages is how attackers harvest other customers\' orders or scrape the whole catalog.',
    actions: () => [
      'Confirm that a customer can only open their own orders. If any order page can be opened by guessing its number, fix that first.',
      'Keep the source address blocked while the activity continues.',
    ],
  },

  payment_abuse_signal: {
    title: 'Repeated payment security events',
    headline: (f) => `Repeated payment security events from ${ip(f)}`,
    what: (f) =>
      `${plural(f.activity.paymentEvents, 'payment security event')} ${f.activity.paymentEvents === 1 ? 'was' : 'were'} recorded from ${ip(f)} ${span(f)}.`,
    why: 'Repeated payment problems from one source can mean someone is testing stolen card numbers or probing the checkout.',
    actions: () => [
      'Review the affected payment attempts with your payment provider.',
      'Watch for chargebacks linked to orders placed from this address.',
    ],
  },

  session_anomaly: {
    title: 'Unusual session behavior',
    headline: (f) => `Unusual session behavior from ${ip(f)}`,
    what: (f) =>
      `${plural(f.activity.sessionAnomalies, 'session anomaly event')} ${f.activity.sessionAnomalies === 1 ? 'was' : 'were'} recorded from ${ip(f)} ${span(f)}.`,
    why: 'Unusual session activity can mean someone is using a stolen login session.',
    actions: () => ['Consider signing out the affected sessions and asking the account holders to log in again.'],
  },
};

/** Used for rule codes without a custom narrative. Built only from stored rule metadata. */
export function fallbackNarrative(code: string, name?: string, description?: string): Narrative {
  const label = name || code;
  return {
    title: label,
    headline: (f) => `${label} detected from ${ip(f)}`,
    what: (f) =>
      `The monitoring system matched the rule "${label}"${description ? ` (${description})` : ''} for activity from ${ip(f)} ${span(f)}.`,
    why: 'This rule was configured by your security team to flag activity that may need review.',
    actions: () => ['Review the technical report for the supporting events.'],
  };
}

export function narrativeFor(code: string | null | undefined, name?: string, description?: string): Narrative {
  if (code && NARRATIVES[code]) return NARRATIVES[code];
  return fallbackNarrative(code || 'unknown', name, description);
}

export function ruleTitle(code: string, name?: string): string {
  return NARRATIVES[code]?.title ?? name ?? code;
}
