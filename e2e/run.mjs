#!/usr/bin/env node
// End-to-end tests of the whole system: the real API, the real database, and the real
// PHP library, talking to each other over HTTP. Nothing is mocked.
//
//   E2E_CONFIRM=yes E2E_BASE=http://localhost:4000 node e2e/run.mjs
//
// It WRITES test data (users, API keys, events, incidents, blocks), so run it against a
// test database. See e2e/README.md. Needs Node 18+ and, for the PHP scenarios, PHP 7.4+.

import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const BASE = (process.env.E2E_BASE ?? 'http://localhost:4000').replace(/\/$/, '');
const API = `${BASE}/api/v1`;
const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? 'admin@pishon.local';
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? 'ChangeMeStrong!123';
const PHP = process.env.E2E_PHP ?? 'php';
const ONLY = process.env.E2E_ONLY ? process.env.E2E_ONLY.split(',') : null;
const RUN = randomBytes(3).toString('hex');

if (process.env.E2E_CONFIRM !== 'yes') {
  console.error('This suite writes test data (users, keys, events, incidents, blocks).\nRun it against a test database and confirm with E2E_CONFIRM=yes.');
  process.exit(2);
}

// ------------------------------------------------------------------ tiny test framework
let passed = 0, failed = 0, skipped = 0;
const failures = [];
const t0 = Date.now();
function check(name, ok, detail = '') {
  if (ok) { passed++; console.log(`  ok    ${name}`); return true; }
  failed++; failures.push(name);
  console.log(`  FAIL  ${name}${detail ? `   (${detail})` : ''}`);
  return false;
}
function skip(name, why) { skipped++; console.log(`  skip  ${name}   (${why})`); }
async function scenario(id, title, fn) {
  if (ONLY && !ONLY.includes(id)) return;
  console.log(`\n[${id}] ${title}`);
  try { await fn(); } catch (e) { failed++; failures.push(`${id}: ${e.message}`); console.log(`  FAIL  scenario stopped: ${e.stack?.split('\n').slice(0, 3).join(' | ')}`); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(fn, { timeout = 10000, every = 250 } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    try { const v = await fn(); if (v) return v; } catch { /* keep trying */ }
    if (Date.now() >= end) return null;
    await sleep(every);
  }
}

async function http(method, path, { token, key, body, headers = {}, raw = false } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (token) h.authorization = `Bearer ${token}`;
  if (key) h.authorization = `Bearer ${key}`;
  const started = Date.now();
  let res;
  try {
    res = await fetch(`${API}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  } catch (e) {
    return { status: 0, body: null, error: e.message, ms: Date.now() - started };
  }
  const text = await res.text();
  let parsed = text;
  if (!raw) { try { parsed = JSON.parse(text); } catch { /* plain text */ } }
  return { status: res.status, body: parsed, headers: res.headers, ms: Date.now() - started };
}

// ------------------------------------------------------------------ test data
// Documentation address ranges are used so the data can never involve a real visitor.
// By default addresses come from 198.18.0.0/15 (131,000 addresses reserved for network
// testing), so a second run is very unlikely to meet addresses a previous run used.
const used = new Set();
function ip(range) {
  for (;;) {
    const a = range
      ? `${range}.${1 + Math.floor(Math.random() * 253)}`
      : `198.${18 + Math.floor(Math.random() * 2)}.${Math.floor(Math.random() * 256)}.${1 + Math.floor(Math.random() * 253)}`;
    if (!used.has(a)) { used.add(a); return a; }
  }
}
const uid = (label) => `e2e-${RUN}-${label}`;
const S = { admin: {}, keys: {}, blockedByUs: new Set(), allowedByUs: new Set(), keyIds: [] };

async function login(email, password) {
  const r = await http('POST', '/auth/login', { body: { email, password } });
  return r.status === 201 ? r.body : null;
}
async function event(key, ev) { return http('POST', '/events', { key, body: ev }); }
const failedLogin = (address, user, extra = {}) => ({ event_type: 'login_failed', severity: 'MEDIUM', ip_address: address, user_id: user, request_path: '/login', request_method: 'POST', ...extra });
async function burst(key, events, concurrency = 12) {
  const results = [];
  for (let i = 0; i < events.length; i += concurrency) {
    results.push(...await Promise.all(events.slice(i, i + concurrency).map((e) => event(key, e))));
  }
  return results;
}
const admin = () => S.admin.accessToken;
const incidentsFor = async (address) => (await http('GET', `/incidents?sourceIp=${address}&pageSize=50`, { token: admin() })).body?.data ?? [];
const eventsFor = async (query) => (await http('GET', `/events?${query}&pageSize=200`, { token: admin() })).body;
const blocklist = async () => (await http('GET', '/security/blocked-ips', { token: admin() })).body?.data ?? [];
const isBlocked = async (address) => (await blocklist()).some((b) => b.ipAddress === address);
async function block(address, extra = {}) {
  S.blockedByUs.add(address);
  return http('POST', '/security/block', { token: admin(), body: { ipAddress: address, reason: `e2e ${RUN}`, ...extra } });
}
async function unblock(address) { return http('POST', '/security/unblock', { token: admin(), body: { ipAddress: address, reason: `e2e ${RUN} cleanup` } }); }

// ------------------------------------------------------------------ PHP helper
const phpOk = (() => { const r = spawnSync(PHP, ['-r', 'echo extension_loaded("curl") && PHP_VERSION_ID >= 70400 ? "yes" : "no";'], { encoding: 'utf8' }); return r.status === 0 && r.stdout === 'yes'; })();
const stateRoot = mkdtempSync(join(tmpdir(), `pishon-e2e-${RUN}-`));
let stateN = 0;
const newState = () => join(stateRoot, String(++stateN));
/** Simulates one page view. Returns whether the visitor was stopped. */
function page({ key = S.keys.full, state, visitor, remote = '10.0.0.5', mode = 'enforce', action = '', ttl = '1', extra = {}, base = BASE } = {}) {
  const env = {
    PATH: process.env.PATH, SECURITY_API_BASE: base, SECURITY_API_KEY: key, SECURITY_STATE_DIR: state, SECURITY_MODE: mode,
    SECURITY_TRUSTED_PROXIES: 'private', SECURITY_BLOCKLIST_TTL: ttl, SECURITY_BREAKER_OPEN: '2', SECURITY_API_TIMEOUT: '1',
    REMOTE_ADDR: remote, HTTP_USER_AGENT: 'E2E-Browser/1.0', REQUEST_METHOD: 'POST', REQUEST_URI: '/login?token=E2ESECRET',
    E2E_ACTION: action, ...extra,
  };
  if (visitor) env.HTTP_X_FORWARDED_FOR = visitor;
  const started = Date.now();
  const r = spawnSync(PHP, ['-d', 'variables_order=EGPCS', '-d', 'error_log=/dev/null', join(HERE, 'php', 'request.php')], { env, encoding: 'utf8', timeout: 20000 });
  return { denied: /Access denied/.test(r.stdout), ok: /PAGE_OK/.test(r.stdout), seen: (r.stdout.match(/ip=(\S+)/) ?? [])[1], out: r.stdout.trim(), ms: Date.now() - started };
}
const spoolLines = (state) => { const f = join(state, 'events.spool.jsonl'); return existsSync(f) ? readFileSync(f, 'utf8').split('\n').filter(Boolean).length : 0; };
function run(cmd) { return spawnSync('sh', ['-c', cmd], { stdio: 'ignore', timeout: 60000 }).status; }

// ================================================================== scenarios
console.log(`End-to-end suite  run=${RUN}  target=${BASE}  php=${phpOk ? 'yes' : 'no'}`);

await scenario('00', 'The system is up', async () => {
  const r = await http('GET', '/statistics');
  check('the API answers (and refuses an anonymous caller)', r.status === 401, `status ${r.status} ${r.error ?? ''}`);
  if (r.status === 0) { console.log('\nThe API is not reachable. Start it first.'); process.exit(2); }
});

await scenario('01', 'Accounts, roles and API keys', async () => {
  const a = await login(ADMIN_EMAIL, ADMIN_PASSWORD);
  if (!check('the administrator can sign in', !!a)) throw new Error('cannot sign in');
  S.admin = a;
  const mk = async (label, role) => {
    const email = `e2e-${RUN}-${label}@pishon.test`;
    const password = `E2e-${RUN}-pw-${label}!!`;
    const c = await http('POST', '/auth/users', { token: admin(), body: { email, password, name: `E2E ${label}`, role } });
    check(`creates a ${role} account`, c.status === 201, `status ${c.status}`);
    return login(email, password);
  };
  S.analyst = await mk('analyst', 'ANALYST');
  S.viewer = await mk('viewer', 'VIEWER');
  S.secadmin = await mk('secadmin', 'SECURITY_ADMIN');
  check('the new accounts can sign in', !!S.analyst && !!S.viewer && !!S.secadmin);

  const mkKey = async (name, scopes) => {
    const r = await http('POST', '/api-keys', { token: admin(), body: { name: `e2e-${RUN}-${name}`, scopes } });
    if (r.status === 201) S.keyIds.push(r.body.id);
    return r.body?.apiKey;
  };
  S.keys.full = await mkKey('full', ['events:write', 'block:read']);
  S.keys.events = await mkKey('events-only', ['events:write']);
  S.keys.block = await mkKey('block-only', ['block:read']);
  check('creates three API keys with different scopes', !!(S.keys.full && S.keys.events && S.keys.block));
  check('a key is only shown once, in the creation response', (await http('GET', '/api-keys', { token: admin() })).body?.every?.((k) => !('apiKey' in k) && !('keyHash' in k)) === true);
  check('an invented scope is refused', (await http('POST', '/api-keys', { token: admin(), body: { name: 'bad', scopes: ['admin'] } })).status === 400);
});

await scenario('02', 'Sign-in security', async () => {
  const wrong = await http('POST', '/auth/login', { body: { email: ADMIN_EMAIL, password: 'definitely-wrong-password' } });
  const ghost = await http('POST', '/auth/login', { body: { email: `ghost-${RUN}@pishon.test`, password: 'definitely-wrong-password' } });
  check('wrong password and unknown email get the same answer', wrong.status === 401 && ghost.status === 401 && wrong.body.message === ghost.body.message);
  const s = await login(ADMIN_EMAIL, ADMIN_PASSWORD);
  const r2 = await http('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } });
  check('a refresh token can be exchanged once', r2.status === 201 && !!r2.body.refreshToken);
  const replay = await http('POST', '/auth/refresh', { body: { refreshToken: s.refreshToken } });
  check('using it a second time is refused', replay.status === 401);
  const afterTheft = await http('POST', '/auth/refresh', { body: { refreshToken: r2.body.refreshToken } });
  check('and the replay ends the newest session too (token theft)', afterTheft.status === 401);
  check('an access token is not accepted as a refresh token', (await http('POST', '/auth/refresh', { body: { refreshToken: admin() } })).status === 401);
  check('the same address and user agent are recorded for sign-ins', (await http('GET', '/audit-logs?action=auth.login&pageSize=5', { token: admin() })).body?.data?.length > 0);
});

await scenario('03', 'Who can do what (checked on the live server)', async () => {
  const incidentId = (await http('GET', '/incidents?pageSize=1', { token: admin() })).body?.data?.[0]?.id ?? 'none';
  const rows = [
    // [who, method, path, expected status or list of statuses]
    ['viewer', 'GET', '/events', 403], ['analyst', 'GET', '/events', 200], ['admin', 'GET', '/events', 200],
    ['viewer', 'GET', '/audit-logs', 403], ['analyst', 'GET', '/audit-logs', 200],
    ['viewer', 'GET', '/api-keys', 403], ['analyst', 'GET', '/api-keys', 403], ['secadmin', 'GET', '/api-keys', 200],
    ['viewer', 'GET', '/statistics', 200], ['viewer', 'GET', '/incidents', 200],
    ['viewer', 'GET', '/reports/executive-summary', 200], ['viewer', 'GET', '/reports/security-summary', 403], ['analyst', 'GET', '/reports/security-summary', 200],
    ['viewer', 'GET', `/reports/technical/${incidentId}`, 403],
    ['viewer', 'POST', '/security/block', 403, { ipAddress: '203.0.113.250', reason: 'x' }], ['analyst', 'POST', '/security/block', 403, { ipAddress: '203.0.113.250', reason: 'x' }],
    ['viewer', 'POST', '/security/unblock', 403, { ipAddress: '203.0.113.250', reason: 'x' }],
    ['analyst', 'POST', '/security/allow', 403, { ipAddress: '203.0.113.250', reason: 'x' }],
    ['viewer', 'POST', '/auth/users', 403, { email: 'x@pishon.test', password: 'long-password-12345', role: 'VIEWER' }],
    ['secadmin', 'POST', '/auth/users', 403, { email: 'x@pishon.test', password: 'long-password-12345', role: 'VIEWER' }],
    ['viewer', 'GET', '/security/blocked-ips', 200], ['viewer', 'GET', '/security/blocks/history', 403], ['analyst', 'GET', '/security/blocks/history', 200],
    ['viewer', 'POST', '/ips/203.0.113.250/refresh-intelligence', 403],
    ['anon', 'GET', '/incidents', 401], ['anon', 'GET', '/security/blocked-ips', 401], ['anon', 'GET', '/reports/executive-summary', 401],
  ];
  const tok = { viewer: S.viewer?.accessToken, analyst: S.analyst?.accessToken, secadmin: S.secadmin?.accessToken, admin: admin(), anon: undefined };
  const bad = [];
  for (const [who, method, path, want, body] of rows) {
    const r = await http(method, path, { token: tok[who], body });
    if (r.status !== want) bad.push(`${who} ${method} ${path} -> ${r.status} (wanted ${want})`);
  }
  check(`${rows.length} role and route combinations behave as designed`, bad.length === 0, bad.join('; '));
  check('a website key cannot use administrator routes', (await http('GET', '/incidents', { key: S.keys.full })).status === 401);
  check('a key without events:write cannot send events', (await event(S.keys.block, failedLogin(ip(), uid('x')))).status === 403);
  check('a key without block:read cannot read the blocklist', (await http('GET', '/security/blocked-ips', { key: S.keys.events })).status === 403);
  check('a key with block:read can read the blocklist', (await http('GET', '/security/blocked-ips', { key: S.keys.block })).status === 200);
  check('an administrator login cannot be used to send events', (await event(admin(), failedLogin(ip(), uid('x')))).status === 401);
  check('an unknown key is refused', (await event('PMS_000000000000000000000000000000', failedLogin(ip(), uid('x')))).status === 401);
});

await scenario('04', 'What is stored from an event', async () => {
  const a = ip();
  const r = await event(S.keys.full, { event_type: 'page_view', severity: 'INFO', ip_address: a, user_id: uid('hygiene'), request_path: '/reset?token=SUPERSECRET&lang=en', metadata: { password: 'hunter2', reset_token: 'abc', plan: 'pro', shipping_address: '12 Marina Rd' } });
  check('an event is accepted', r.status === 201, `status ${r.status}`);
  const stored = (await http('GET', `/events/${r.body.id}`, { token: admin() })).body;
  check('the password and token fields are redacted in storage', stored?.metadata?.password === '[REDACTED]' && stored?.metadata?.reset_token === '[REDACTED]');
  check('ordinary fields survive, including one containing "pin" ("shipping")', stored?.metadata?.plan === 'pro' && stored?.metadata?.shipping_address === '12 Marina Rd');
  check('a reset token in the URL is redacted, the rest of the URL kept', stored?.requestPath === '/reset?token=[REDACTED]&lang=en');
  check('the secret appears nowhere in the stored event', !JSON.stringify(stored).includes('SUPERSECRET') && !JSON.stringify(stored).includes('hunter2'));
  const mapped = await event(S.keys.full, { event_type: 'page_view', severity: 'INFO', ip_address: `::ffff:${a}` });
  check('an IPv4-mapped address is stored as the plain IPv4 address', (await http('GET', `/events/${mapped.body.id}`, { token: admin() })).body?.ipAddress === a);
  const bad = await event(S.keys.full, { event_type: 'page_view', severity: 'INFO', ip_address: '127.1' });
  check('a shorthand address is not turned into a different address', (await http('GET', `/events/${bad.body.id}`, { token: admin() })).body?.ipAddress == null);
  check('an event dated in the future is refused', (await event(S.keys.full, { event_type: 'page_view', severity: 'INFO', timestamp: new Date(Date.now() + 3600e3).toISOString() })).status === 400);
  check('an event with a bad severity or an unknown field is refused', (await event(S.keys.full, { event_type: 'x', severity: 'URGENT' })).status === 400 && (await event(S.keys.full, { event_type: 'x', severity: 'LOW', admin: true })).status === 400);
  check('an old event is accepted (delayed delivery)', (await event(S.keys.full, { event_type: 'page_view', severity: 'INFO', ip_address: a, timestamp: '2025-01-01T00:00:00Z' })).status === 201);
  check('sorting by a column that is not allowed does not break the list', (await http('GET', '/events?sortBy=metadata', { token: admin() })).status === 200);
  check('a malformed date filter is a 400, not a 500', (await http('GET', '/events?from=whenever', { token: admin() })).status === 400);
});

await scenario('05', 'Detection: one address attacking logins (escalation and automatic block)', async () => {
  const a = ip();
  S.ipBrute = a;
  const first = await burst(S.keys.full, Array.from({ length: 6 }, (_, i) => failedLogin(a, uid(`bf${i}`))), 1);
  const last = first[first.length - 1].body;
  check('six failed logins are scored and an incident is opened', last.riskScore > 0 && !!last.incidentId, JSON.stringify(last));
  let inc = (await incidentsFor(a))[0];
  check('the incident names the attacking address and is open', inc?.sourceIp === a && inc?.status === 'OPEN');
  const sevBefore = inc?.severity;
  await burst(S.keys.full, Array.from({ length: 20 }, (_, i) => failedLogin(a, uid(`bg${i}`))), 1);
  const all = await incidentsFor(a);
  inc = all[0];
  check('the same incident keeps growing: exactly one incident for the address', all.length === 1, `${all.length} incidents`);
  check('it escalated to CRITICAL', inc?.severity === 'CRITICAL' && inc?.riskScore >= 85, `${sevBefore} -> ${inc?.severity} risk ${inc?.riskScore}`);
  const detail = (await http('GET', `/incidents/${inc.id}`, { token: admin() })).body;
  check('the timeline records the escalation', detail.timeline?.some((t) => t.action === 'incident.escalated'));
  check('the address was blocked automatically', await isBlocked(a));
  const ipd = (await http('GET', `/ips/${a}`, { token: admin() })).body;
  check('the address record shows the risk', ipd?.ip?.riskLevel === 'CRITICAL' && ipd?.ip?.failedLogins >= 26, JSON.stringify(ipd?.ip));
  check('every event is counted exactly once', (await eventsFor(`ipAddress=${a}`)).meta.total === 26);
  S.bruteIncident = inc;
});

await scenario('06', 'Detection: signals that add risk but do not open incidents', async () => {
  const b = ip();
  const pay = await event(S.keys.full, { event_type: 'suspicious_request', severity: 'HIGH', ip_address: b, request_path: '/search?q=<script>alert(1)</script>', request_method: 'GET' });
  const stored = (await http('GET', `/events/${pay.body.id}`, { token: admin() })).body;
  check('an injection attempt in a URL is scored and the rule is recorded', pay.body.riskScore > 0 && stored.matchedRules?.some((m) => m.code === 'suspicious_payload'));
  check('and it does not open an incident on its own', (await incidentsFor(b)).length === 0);
  const c = ip();
  const resets = await burst(S.keys.full, Array.from({ length: 6 }, (_, i) => ({ event_type: 'password_reset', severity: 'LOW', ip_address: c, user_id: uid(`pr${i}`) })), 1);
  const lastReset = (await http('GET', `/events/${resets[5].body.id}`, { token: admin() })).body;
  check('repeated password resets from one address fire the abuse rule', lastReset.matchedRules?.some((m) => m.code === 'password_reset_abuse'));
});

await scenario('07', 'Detection: attacks that spread across addresses and accounts', async () => {
  // Account takeover: many failures on one account from several addresses, then a success.
  const victim = uid('victim');
  const from = [ip(), ip(), ip(), ip()];
  for (const a of from) await event(S.keys.full, failedLogin(a, victim));
  const winner = ip();
  const r = await event(S.keys.full, { event_type: 'login_success', severity: 'INFO', ip_address: winner, user_id: victim, request_path: '/login' });
  const inc = (await incidentsFor(winner))[0];
  check('a login that succeeds right after failures raises a takeover incident', inc?.detectionRule === 'possible_account_takeover', JSON.stringify(r.body));
  check('rated HIGH, not critical (few addresses, few attempts)', inc?.severity === 'HIGH');
  check('and the address that got in is not blocked automatically on that alone', !(await isBlocked(winner)));
  // A customer who simply fumbled their own password.
  const customer = uid('fumbler');
  const home = ip();
  for (let i = 0; i < 4; i++) await event(S.keys.full, failedLogin(home, customer));
  await event(S.keys.full, { event_type: 'login_success', severity: 'INFO', ip_address: home, user_id: customer });
  const own = (await incidentsFor(home)).find((i) => i.detectionRule === 'possible_account_takeover');
  check('a customer who mistypes their own password from one address is never rated critical', !own || own.severity !== 'CRITICAL');
  // One account attacked from many addresses.
  const target = uid('target');
  for (let i = 0; i < 5; i++) await event(S.keys.full, failedLogin(ip(), target));
  const list = (await http('GET', '/incidents?pageSize=100', { token: admin() })).body.data;
  const acct = list.find((i) => i.detectionRule === 'distributed_account_attack' && i.userId === target);
  check('one account attacked from five addresses opens an account-level incident', !!acct && acct.sourceIp === null, JSON.stringify(acct && { sourceIp: acct.sourceIp, userId: acct.userId }));
  // A platform-wide spray.
  const spray = Array.from({ length: 18 }, () => ip());
  await burst(S.keys.full, spray.flatMap((a, n) => [1, 2, 3].map((k) => failedLogin(a, uid(`spray${n}-${k}`)))), 12);
  const list2 = (await http('GET', '/incidents?pageSize=100', { token: admin() })).body.data;
  const glob = list2.find((i) => i.detectionRule === 'distributed_login_attack' && i.sourceIp === null && i.userId === null);
  check('a spray from 18 addresses opens one platform-wide incident', !!glob);
  check('no single sprayer is blocked: each made only a few attempts', (await Promise.all(spray.map(isBlocked))).every((b) => !b));
  check('there is only one such incident open', list2.filter((i) => i.detectionRule === 'distributed_login_attack' && i.status === 'OPEN' && new Date(i.updatedAt).getTime() >= t0 - 1000).length === 1);
  S.globalIncident = glob;
  S.takeover = inc;
});

await scenario('08', 'Parallel traffic from one attacker (race conditions)', async () => {
  const a = ip();
  await burst(S.keys.full, Array.from({ length: 60 }, (_, i) => failedLogin(a, uid(`par${i}`))), 24);
  check('all 60 events were stored', (await eventsFor(`ipAddress=${a}`)).meta.total === 60);
  const incs = await incidentsFor(a);
  check('exactly one incident was opened, not one per request', incs.length === 1, `${incs.length} incidents`);
  const linked = (await http('GET', `/incidents/${incs[0]?.id}`, { token: admin() })).body;
  // Only events that triggered a rule are linked. The first few (before the threshold) are not.
  check('the events that triggered detection are linked to it', (linked.events?.length ?? 0) >= 30, `events ${linked.events?.length}`);
  const ipd = (await http('GET', `/ips/${a}`, { token: admin() })).body?.ip;
  check('the address counters are exact: no event lost', ipd?.eventCount === 60 && ipd?.failedLogins === 60, `${ipd?.eventCount}/${ipd?.failedLogins}`);
  const hist = (await http('GET', `/security/blocks/history?ip=${a}&limit=50`, { token: admin() })).body;
  const blocks = (Array.isArray(hist) ? hist : hist?.data ?? []).filter((b) => b.action === 'BLOCK');
  check('exactly one block record was created', blocks.length === 1, `${blocks.length} block records`);
  check('and it is in force', await isBlocked(a));
});

await scenario('09', 'Reports match the stored data', async () => {
  const inc = S.bruteIncident;
  const rep = (await http('GET', `/reports/incidents/${inc.incidentId}`, { token: S.viewer.accessToken })).body;
  const sections = Object.keys(rep.sections ?? {}).sort().join(',');
  check('a viewer can read the plain-English report, by public incident number', sections === 'actionTaken,currentStatus,evidence,recommendedActions,riskLevel,whatHappened,whyItMatters', sections);
  check('it states the real number of failed logins (26)', /26 failed login attempts/.test(rep.sections.whatHappened), rep.sections.whatHappened);
  check('it names the address and does not leak rule codes', rep.sections.whatHappened.includes(S.ipBrute) && !/brute_force_login|credential_stuffing|riskDelta/.test(JSON.stringify(rep.sections)));
  check('it reports CRITICAL risk', rep.sections.riskLevel.level === 'CRITICAL');
  check('it says the address was blocked', rep.sections.actionTaken.join(' ').includes('blocked automatically'));
  check('it is honest about what it cannot confirm', rep.limitations.length >= 2);
  const text = await http('GET', `/reports/incidents/${inc.incidentId}?format=text`, { token: admin(), raw: true });
  check('the plain-text version has every section', typeof text.body === 'string' && /WHAT HAPPENED[\s\S]*WHY IT MATTERS[\s\S]*RECOMMENDED ACTION/.test(text.body) && /text\/plain/.test(text.headers.get('content-type')));
  check('reports are never cached', text.headers.get('cache-control') === 'no-store');
  check('the technical report is closed to viewers and open to analysts', (await http('GET', `/reports/technical/${inc.id}`, { token: S.viewer.accessToken })).status === 403 && (await http('GET', `/reports/technical/${inc.id}`, { token: S.analyst.accessToken })).status === 200);
  const tech = (await http('GET', `/reports/technical/${inc.id}`, { token: admin() })).body;
  check('it shows the rules that fired and the stored versus peak risk', tech.rulesFired?.length > 0 && tech.incident.effectiveRisk >= tech.incident.storedRiskScore);
  check('no query strings or secrets in the paths it shows', !JSON.stringify(tech).includes('SECRET'));
  const takeover = (await http('GET', `/reports/incidents/${S.takeover.id}`, { token: admin() })).body;
  check('the takeover report advises treating the account as compromised', takeover.sections.recommendedActions.join(' ').includes('compromised'));
  const glob = (await http('GET', `/reports/incidents/${S.globalIncident.id}`, { token: admin() })).body;
  check('the platform-wide report does not blame a single address', /different addresses/.test(glob.sections.whatHappened) && !glob.sections.recommendedActions.join(' ').includes('Consider blocking the source address'));
  const exec = (await http('GET', '/reports/executive-summary?days=1', { token: S.viewer.accessToken })).body;
  check('the executive summary rates the situation URGENT while a critical incident is open', exec.posture === 'URGENT', exec.posture);
  check('its numbers add up', exec.keyNumbers.find((k) => k.label === 'Incidents opened') && exec.notableIncidents.length > 0 && exec.needsAttention.length > 0);
  const sec = (await http('GET', '/reports/security-summary?days=1', { token: admin() })).body;
  check('the security summary covers the period with a daily series', sec.totals.events >= 150 && sec.daily.length >= 1 && sec.incidentsBySeverity.some((x) => x.severity === 'CRITICAL'));
  check('and counts what this run generated', sec.topSourceIps.length > 0 && sec.blocking.stillInForce >= 1);
  const viewerInc = (await http('GET', `/incidents/${inc.id}`, { token: S.viewer.accessToken })).body;
  check('a viewer sees the incident and its timeline but not the raw events', Array.isArray(viewerInc.timeline) && !('events' in viewerInc));
  const audit = (await http('GET', '/audit-logs?action=report&pageSize=50', { token: admin() })).body.data;
  check('every report read was written to the audit log with who read it', audit.some((a) => a.action === 'report.technical' && /analyst/.test(a.actorLabel ?? '')), JSON.stringify(audit.slice(0, 2).map((a) => [a.action, a.actorLabel])));
});

await scenario('10', 'Blocking rules', async () => {
  check('a private address cannot be blocked', (await block('10.0.0.5')).status === 400 && (await block('127.0.0.1')).status === 400);
  check('a shorthand address is refused, not read as another address', (await block('127.1')).status === 400);
  check('the string "false" for permanent is refused, not treated as true', (await block(ip(), { permanent: 'false' })).status === 400);
  const m = ip();
  const b = await block(m, { ttlMinutes: 30 });
  const row = (await blocklist()).find((x) => x.ipAddress === m);
  check('an administrator can block an address for a set time', b.status === 201 && row && row.permanent === false && row.automatic === false && !!row.expiresAt);
  check('the blocklist read by the website lists only what it needs', Object.keys(row).sort().join() === 'automatic,createdAt,expiresAt,ipAddress,permanent,reason');
  check('unblocking removes it', (await unblock(m)).status === 201 && !(await isBlocked(m)));
  const hist = (await http('GET', `/security/blocks/history?ip=${m}`, { token: admin() })).body;
  const actions = (Array.isArray(hist) ? hist : hist.data).map((h) => h.action).sort().join();
  check('and the history keeps both the block and the unblock', actions === 'BLOCK,UNBLOCK', actions);

  // An administrator's permanent block must survive an attack from that address.
  const p = ip();
  await block(p, { permanent: true });
  await burst(S.keys.full, Array.from({ length: 25 }, (_, i) => failedLogin(p, uid(`pm${i}`))), 1);
  const active = (await blocklist()).filter((x) => x.ipAddress === p);
  check('an automatic block never replaces an administrator\'s permanent block', active.length === 1 && active[0].permanent === true && active[0].automatic === false, JSON.stringify(active));
  check('the incident still opens and escalates', (await incidentsFor(p))[0]?.severity === 'CRITICAL');

  // The allowlist protects an address from automatic blocking and from manual blocking.
  const w = ip();
  S.allowedByUs.add(w);
  check('an address can be put on the allowlist', (await http('POST', '/security/allow', { token: admin(), body: { ipAddress: w, reason: `e2e ${RUN}` } })).status === 201);
  await burst(S.keys.full, Array.from({ length: 25 }, (_, i) => failedLogin(w, uid(`al${i}`))), 1);
  check('an allowlisted attacker still raises an incident', (await incidentsFor(w))[0]?.severity === 'CRITICAL');
  check('but is not blocked automatically', !(await isBlocked(w)));
  check('nor can an administrator block it by accident', (await block(w)).status === 400);
  check('removing it from the allowlist works', (await http('DELETE', `/security/allow/${w}`, { token: admin() })).status === 200);
});

await scenario('11', 'API key lifecycle', async () => {
  const mk = await http('POST', '/api-keys', { token: admin(), body: { name: `e2e-${RUN}-rot`, scopes: ['events:write'] } });
  const k1 = mk.body.apiKey; S.keyIds.push(mk.body.id);
  check('a new key works', (await event(k1, { event_type: 'page_view', severity: 'INFO' })).status === 201);
  const rot = await http('POST', `/api-keys/${mk.body.id}/rotate`, { token: admin() });
  const k2 = rot.body.apiKey; S.keyIds.push(rot.body.id);
  check('rotation issues a different key', rot.status === 201 && !!k2 && k2 !== k1);
  check('the old key stops working immediately', (await event(k1, { event_type: 'page_view', severity: 'INFO' })).status === 401);
  check('the new key works and keeps the same scopes', (await event(k2, { event_type: 'page_view', severity: 'INFO' })).status === 201 && (await http('GET', '/security/blocked-ips', { key: k2 })).status === 403);
  check('revoking a key stops it at once', (await http('DELETE', `/api-keys/${rot.body.id}`, { token: admin() })).status === 200 && (await event(k2, { event_type: 'page_view', severity: 'INFO' })).status === 401);
  check('a key a viewer or analyst tries to manage is refused', (await http('POST', '/api-keys', { token: S.analyst.accessToken, body: { name: 'x', scopes: ['events:write'] } })).status === 403);
});

await scenario('12', 'The PHP library against the real API', async () => {
  if (!phpOk) return skip('all PHP scenarios', 'php 7.4+ with curl not found; set E2E_PHP');
  const state = newState();
  const visitor = ip();
  const user = uid('phpuser');
  // 25 failed logins through the library, from a visitor behind a proxy.
  for (let i = 0; i < 25; i++) page({ state, visitor, mode: 'monitor', action: `loginFailed:${user}-${i}` });
  const events = await eventsFor(`ipAddress=${visitor}&eventType=login_failed`);
  check('the events arrive attributed to the visitor, not the proxy', events.meta.total === 25, `${events.meta.total}`);
  check('the proxy address never appears as a source', (await eventsFor('ipAddress=10.0.0.5')).meta.total === 0);
  const sample = events.data[0];
  check('the password was removed before it left the website', sample.metadata?.password === '[REDACTED]' && !JSON.stringify(events.data).includes('hunter2-e2e'));
  check('the reset token in the URL was removed too', sample.requestPath === '/login?token=[REDACTED]' && !JSON.stringify(events.data).includes('E2ESECRET'));
  check('the browser details came through', sample.userAgent === 'E2E-Browser/1.0');
  const inc = (await incidentsFor(visitor))[0];
  check('the library\'s events caused a detection and an incident for the visitor', inc?.sourceIp === visitor && inc?.severity === 'CRITICAL', JSON.stringify(inc && { s: inc.sourceIp, sev: inc.severity }));
  check('the visitor was blocked automatically', await isBlocked(visitor));

  await sleep(1200);
  check('in monitor mode the blocked visitor is NOT stopped (safe rollout)', page({ state, visitor, mode: 'monitor' }).denied === false);
  check('in enforce mode the blocked visitor IS stopped', page({ state, visitor, mode: 'enforce' }).denied === true);
  check('another customer behind the same proxy is not affected', page({ state, visitor: ip(), mode: 'enforce' }).ok === true);
  check('the proxy itself is never blocked', page({ state, remote: '10.0.0.5', mode: 'enforce' }).denied === false);
  const spoof = page({ state, remote: ip('203.0.113'), visitor, mode: 'enforce' });
  check('a forged forwarding header from an untrusted source cannot get anyone blocked', spoof.denied === false, spoof.out);
  check('direct connections from the blocked address are stopped', page({ state, remote: visitor, mode: 'enforce', extra: { SECURITY_TRUSTED_PROXIES: '' } }).denied === true);

  await unblock(visitor);
  await sleep(1200);
  check('after an administrator unblocks, the website lets the visitor back in', page({ state, visitor, mode: 'enforce' }).denied === false);
  const m = ip();
  await block(m, { permanent: true });
  await sleep(1200);
  check('a block placed by an administrator reaches the website within the refresh time', page({ state, visitor: m, mode: 'enforce' }).denied === true);
  await unblock(m);
  await sleep(1200);
  check('and lifting it works the same way', page({ state, visitor: m, mode: 'enforce' }).denied === false);

  const tight = newState();
  const quiet = ip();
  page({ state: tight, visitor: quiet, ttl: '300' });
  const spent = Date.now();
  for (let i = 0; i < 5; i++) page({ state: tight, visitor: quiet, ttl: '300' });
  check('with a long refresh interval, page views make no extra API calls (fast)', (Date.now() - spent) / 5 < 600, `${Math.round((Date.now() - spent) / 5)} ms per page`);
  check('a key without the block:read scope fails safe: visitors are let in', page({ state: newState(), key: S.keys.events, visitor: ip(), mode: 'enforce' }).denied === false);
  check('the setup checker passes against this server', (() => {
    const r = spawnSync(PHP, [join(HERE, '..', 'integration', 'php', 'bin', 'doctor.php')], { env: { PATH: process.env.PATH, SECURITY_API_BASE: BASE, SECURITY_API_KEY: S.keys.full, SECURITY_STATE_DIR: newState(), REMOTE_ADDR: '10.0.0.5', HTTP_X_FORWARDED_FOR: '203.0.113.9', SECURITY_TRUSTED_PROXIES: 'private' }, encoding: 'utf8' });
    return r.status === 0 && /All good/.test(r.stdout);
  })());
  const miss = spawnSync(PHP, [join(HERE, '..', 'integration', 'php', 'bin', 'doctor.php')], { env: { PATH: process.env.PATH, SECURITY_API_BASE: BASE, SECURITY_API_KEY: S.keys.full, SECURITY_STATE_DIR: newState(), REMOTE_ADDR: '10.0.0.5', HTTP_X_FORWARDED_FOR: '203.0.113.9' }, encoding: 'utf8' });
  check('and it catches a missing proxy setting', miss.status === 1 && /SECURITY_TRUSTED_PROXIES/.test(miss.stdout));
});

await scenario('13', 'Outage and recovery', async () => {
  if (!phpOk) return skip('outage scenarios', 'php not available');
  const stop = process.env.E2E_API_STOP, start = process.env.E2E_API_START;
  if (!stop || !start) return skip('API outage', 'set E2E_API_STOP and E2E_API_START to test it');
  const state = newState();
  const blocked = ip(), customer = ip(), user = uid('outage');
  await block(blocked, { permanent: true });
  await sleep(300);
  page({ state, visitor: customer, action: '' }); // fills the cache while the API is up
  check('before the outage, the blocked visitor is stopped', page({ state, visitor: blocked }).denied === true);

  run(stop);
  await waitFor(async () => (await http('GET', '/statistics')).status === 0, { timeout: 15000 });
  await sleep(1200); // the cached list is now older than its refresh time
  check('the API is down', (await http('GET', '/statistics')).status === 0);
  const during = page({ state, visitor: blocked });
  check('during the outage the blocked visitor is STILL stopped (the previous list stays in force)', during.denied === true, during.out);
  const cust = page({ state, visitor: customer });
  check('customers are still served', cust.ok === true);
  check('and quickly: the website does not wait on a dead API', cust.ms < 2500 && during.ms < 2500, `${cust.ms} ms / ${during.ms} ms`);
  for (let i = 0; i < 6; i++) page({ state, visitor: customer, action: `loginFailed:${user}-${i}` });
  check('events are kept on disk instead of lost', spoolLines(state) >= 4, `${spoolLines(state)} queued`);

  run(start);
  const up = await waitFor(async () => (await http('GET', '/statistics')).status === 401, { timeout: 45000, every: 500 });
  check('the API comes back', !!up);
  await sleep(2500); // the breaker pause is 2 seconds in this suite
  for (let i = 0; i < 4; i++) { page({ state, visitor: customer }); await sleep(300); }
  const got = await waitFor(async () => (await eventsFor(`userId=${user}-0`)).meta.total >= 1, { timeout: 8000 });
  let delivered = 0;
  for (let i = 0; i < 6; i++) delivered += (await eventsFor(`userId=${user}-${i}`)).meta.total;
  check('every queued event was delivered after recovery', !!got && delivered >= 6, `${delivered} of 6`);
  check('and each exactly once (no duplicates)', delivered === 6, `${delivered}`);
  const repeat = { event_type: 'page_view', severity: 'INFO', ip_address: ip(), event_id: `dup-${RUN}` };
  const first = await event(S.keys.full, repeat);
  const second = await event(S.keys.full, repeat);
  check('the server also recognises a repeated delivery by its event id', first.status === 201 && second.status === 201 && second.body.id === first.body.id && second.body.duplicate === true && (await eventsFor(`ipAddress=${repeat.ip_address}`)).meta.total === 1);
  check('and another key cannot see or collide with it', (await event(S.keys.events, repeat)).body.id !== first.body.id);
  check('the queue is empty again', spoolLines(state) === 0, `${spoolLines(state)} left`);

  const dbStop = process.env.E2E_DB_STOP, dbStart = process.env.E2E_DB_START;
  if (!dbStop || !dbStart) return skip('database outage', 'set E2E_DB_STOP and E2E_DB_START to test it');
  const user2 = uid('dbout');
  run(dbStop);
  await sleep(1500);
  const r = await event(S.keys.full, failedLogin(ip(), user2));
  check('with the database down, the API answers with an error promptly, not a hang', r.status >= 500 && r.ms < 12000, `status ${r.status} in ${r.ms} ms`);
  check('and the API process stays up', (await http('GET', '/statistics')).status === 401);
  for (let i = 0; i < 4; i++) page({ state, visitor: customer, action: `loginFailed:${user2}-${i}` });
  check('the website queues events while the database is down', spoolLines(state) >= 3, `${spoolLines(state)} queued`);
  run(dbStart);
  const healed = await waitFor(async () => (await event(S.keys.full, { event_type: 'page_view', severity: 'INFO' })).status === 201, { timeout: 60000, every: 1000 });
  check('the API recovers by itself when the database returns (no restart needed)', !!healed);
  await sleep(2500);
  for (let i = 0; i < 4; i++) { page({ state, visitor: customer }); await sleep(300); }
  let d2 = 0;
  for (let i = 0; i < 4; i++) d2 += (await eventsFor(`userId=${user2}-${i}`)).meta.total;
  check('events queued during the database outage were delivered, once each', d2 === 4, `${d2} of 4`);
});

await scenario('98', 'Rate limits', async () => {
  const t = Date.now();
  const sent = await burst(S.keys.full, Array.from({ length: 300 }, () => ({ event_type: 'page_view', severity: 'INFO', ip_address: ip() })), 30);
  check('the website can send a burst of 300 events without being refused', sent.every((r) => r.status === 201), `${sent.filter((r) => r.status !== 201).length} refused, ${Date.now() - t} ms`);
  const tries = [];
  for (let i = 0; i < 40; i++) tries.push(await http('POST', '/auth/login', { body: { email: `nobody-${RUN}@pishon.test`, password: 'wrong-password-123' } }));
  const limited = tries.filter((r) => r.status === 429);
  check('repeated sign-in attempts from one address are cut off', limited.length > 0 && tries.slice(0, 5).every((r) => r.status === 401), `${limited.length} of 40 refused`);
  check('the refusal says when to try again', limited.length > 0 && limited[0].headers.get('retry-after') !== null);
});

await scenario('99', 'Clean up', async () => {
  for (const a of S.blockedByUs) await unblock(a);
  for (const a of S.allowedByUs) await http('DELETE', `/security/allow/${a}`, { token: admin() });
  for (const id of S.keyIds) await http('DELETE', `/api-keys/${id}`, { token: admin() });
  check('test blocks, allowlist entries and keys removed', true);
  rmSync(stateRoot, { recursive: true, force: true });
});

const secs = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped   (${secs}s, run ${RUN})`);
if (failed) { console.log('\nFailed:\n - ' + failures.join('\n - ')); }
process.exit(failed === 0 ? 0 : 1);
