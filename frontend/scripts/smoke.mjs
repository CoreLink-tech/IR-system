#!/usr/bin/env node
/**
 * Contract smoke test. Talks to a LIVE Security API the way the dashboard does (cookie session,
 * CSRF token, Origin header) and checks that every response the dashboard reads has the shape
 * the dashboard expects. It creates a little data (an API key, test events, two test accounts)
 * and cleans up after itself where the API allows.
 *
 *   SMOKE_API=http://localhost:4000 SMOKE_ORIGIN=http://localhost:5173 \
 *   SMOKE_EMAIL=admin@example.com SMOKE_PASSWORD=... npm run smoke
 *
 * The account must be a SUPER_ADMIN. Use a test or staging server, not production.
 */
const API = (process.env.SMOKE_API || 'http://localhost:4000').replace(/\/+$/, '');
const ORIGIN = process.env.SMOKE_ORIGIN || 'http://localhost:5173';
const EMAIL = process.env.SMOKE_EMAIL;
const PASSWORD = process.env.SMOKE_PASSWORD;
if (!EMAIL || !PASSWORD) { console.error('Set SMOKE_EMAIL and SMOKE_PASSWORD (a super admin on a test server).'); process.exit(2); }

const RUN = Date.now().toString(36);
let passed = 0, failed = 0;
const fails = [];
const check = (name, ok, detail = '') => { if (ok) passed++; else { failed++; fails.push(`${name}${detail ? `: ${detail}` : ''}`); } };
const T = { string: (v) => typeof v === 'string', number: (v) => typeof v === 'number', boolean: (v) => typeof v === 'boolean', array: Array.isArray, object: (v) => v && typeof v === 'object' && !Array.isArray(v), nullableString: (v) => v === null || typeof v === 'string' };
function shape(name, obj, spec) {
  if (!T.object(obj)) return check(`${name} is an object`, false, JSON.stringify(obj)?.slice(0, 120));
  for (const [k, t] of Object.entries(spec)) check(`${name}.${k} is ${t}`, T[t](obj[k]), `got ${JSON.stringify(obj[k])?.slice(0, 60)}`);
}

// A tiny cookie jar, scoped like the browser would: the refresh cookie only goes to /api/v1/auth.
const jar = new Map();
function store(res) { for (const c of res.headers.getSetCookie?.() ?? []) { const [pair] = c.split(';'); const i = pair.indexOf('='); const n = pair.slice(0, i), v = pair.slice(i + 1); if (/Max-Age=0/i.test(c) || v === '') jar.delete(n); else jar.set(n, { v, raw: c }); } }
const cookieHeader = (path) => (path.startsWith('/auth') ? [...jar].map(([n, c]) => `${n}=${c.v}`).join('; ') : '');

async function call(method, path, { token, body, headers = {}, key, text } = {}) {
  const h = { Origin: ORIGIN, Accept: 'application/json', ...headers };
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (token) h.Authorization = `Bearer ${token}`;
  if (key) h.Authorization = `Bearer ${key}`; // website keys are sent as a Bearer token
  const ck = cookieHeader(path); if (ck) h.Cookie = ck;
  const res = await fetch(`${API}/api/v1${path}`, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
  store(res);
  const raw = await res.text();
  let json; try { json = JSON.parse(raw); } catch { json = undefined; }
  return { status: res.status, headers: res.headers, json, text: raw };
}

const login = async (email, password) => {
  const r = await call('POST', '/auth/login', { body: { email, password, useCookie: true } });
  return r;
};

async function main() {
  // ---- health and sign in ----
  const h = await call('GET', '/health');
  check('health answers 200', h.status === 200); shape('health', h.json, { status: 'string', service: 'string', version: 'string', time: 'string' });
  check('health leaks nothing extra', Object.keys(h.json).sort().join() === 'service,status,time,version');

  const l = await login(EMAIL, PASSWORD);
  check('login (cookie mode) succeeds', l.status === 201, `status ${l.status}`);
  if (l.status !== 201) throw new Error('cannot sign in; stopping');
  shape('login', l.json, { accessToken: 'string', csrfToken: 'string', user: 'object' });
  shape('login.user', l.json.user, { id: 'string', email: 'string', role: 'string', isActive: 'boolean', mustChangePassword: 'boolean' });
  check('login keeps the refresh token out of the body', l.json.refreshToken === undefined);
  check('login set an httpOnly SameSite=Strict cookie scoped to the auth routes', /HttpOnly/i.test(jar.get('ir_rt')?.raw || '') && /SameSite=Strict/i.test(jar.get('ir_rt')?.raw || '') && /Path=\/api\/v1\/auth/i.test(jar.get('ir_rt')?.raw || ''));
  check('the cookie is not sent to ordinary routes', cookieHeader('/incidents') === '');
  check('me role is SUPER_ADMIN (the smoke test needs it)', l.json.user.role === 'SUPER_ADMIN', l.json.user.role);
  let token = l.json.accessToken;
  const A = (m, p, o = {}) => call(m, p, { token, ...o });

  // ---- session: csrf and rotation ----
  const c1 = await call('GET', '/auth/csrf');
  check('csrf endpoint answers with the cookie', c1.status === 200 && T.string(c1.json?.csrfToken));
  const noCsrf = await call('POST', '/auth/refresh', { body: {} });
  check('refresh without a CSRF token is refused (403, csrf_invalid)', noCsrf.status === 403 && noCsrf.json?.code === 'csrf_invalid', `${noCsrf.status} ${noCsrf.json?.code}`);
  const evil = await call('POST', '/auth/refresh', { body: {}, headers: { Origin: 'https://evil.example', 'X-CSRF-Token': c1.json.csrfToken } });
  check('refresh from a foreign origin is refused (403, origin_not_allowed)', evil.status === 403 && evil.json?.code === 'origin_not_allowed');
  const old = jar.get('ir_rt').v;
  const r1 = await call('POST', '/auth/refresh', { body: {}, headers: { 'X-CSRF-Token': c1.json.csrfToken } });
  check('refresh with cookie + CSRF works and rotates', r1.status === 201 && jar.get('ir_rt').v !== old);
  shape('refresh', r1.json, { accessToken: 'string', csrfToken: 'string', user: 'object' });
  token = r1.json.accessToken;
  const keep = new Map(jar);
  const reuse = await (async () => { const saved = new Map(jar); jar.set('ir_rt', { v: old, raw: '' }); const x = await call('POST', '/auth/refresh', { body: {}, headers: { 'X-CSRF-Token': c1.json.csrfToken } }); jar.clear(); for (const [k, v] of saved) jar.set(k, v); return x; })();
  check('re-using the old refresh token is theft: 401 with code refresh_token_reuse', reuse.status === 401 && reuse.json?.code === 'refresh_token_reuse', `${reuse.status} ${reuse.json?.code}`);
  const after = await call('GET', '/auth/csrf');
  const afterRefresh = await call('POST', '/auth/refresh', { body: {}, headers: { 'X-CSRF-Token': after.json?.csrfToken || 'x' } });
  check('after theft detection the newest session is also ended', afterRefresh.status === 401);
  const again = await login(EMAIL, PASSWORD);
  check('signing in again works', again.status === 201); token = again.json.accessToken;
  void keep;

  // ---- who am I, users, assignees ----
  const me = await A('GET', '/auth/me'); check('me 200', me.status === 200); shape('me', me.json, { id: 'string', email: 'string', role: 'string', isActive: 'boolean', mustChangePassword: 'boolean' });
  const users = await A('GET', '/auth/users'); check('users 200', users.status === 200 && T.array(users.json?.data));
  for (const u of users.json.data.slice(0, 3)) { shape('user', u, { id: 'string', email: 'string', role: 'string', isActive: 'boolean', mustChangePassword: 'boolean', createdAt: 'string' }); check('user list has no password hash', !('passwordHash' in u)); }
  const asg = await A('GET', '/auth/assignees'); check('assignees 200', asg.status === 200 && T.array(asg.json?.data));
  for (const u of asg.json.data.slice(0, 2)) shape('assignee', u, { id: 'string', email: 'string', role: 'string' });

  // user administration safeguards, live
  const pw = `Smoke-${RUN}-Pass1!`;
  const analyst = await A('POST', '/auth/users', { body: { email: `smoke-analyst-${RUN}@example.test`, password: pw, role: 'ANALYST', requirePasswordChange: true } });
  check('create analyst', analyst.status === 201 && analyst.json?.role === 'ANALYST', `${analyst.status}`);
  const viewer = await A('POST', '/auth/users', { body: { email: `smoke-viewer-${RUN}@example.test`, password: pw, role: 'VIEWER' } });
  check('create viewer', viewer.status === 201);
  const self = await A('PATCH', `/auth/users/${me.json.id}`, { body: { role: 'VIEWER' } });
  check('cannot demote yourself (400, self_change_forbidden)', self.status === 400 && self.json?.code === 'self_change_forbidden', `${self.status} ${self.json?.code}`);
  const selfOff = await A('PATCH', `/auth/users/${me.json.id}`, { body: { isActive: false } });
  check('cannot deactivate yourself', selfOff.status === 400);
  const selfReset = await A('POST', `/auth/users/${me.json.id}/reset-password`, { body: { newPassword: 'Another-Long-Pass-1' } });
  check('cannot reset your own password through the admin route', selfReset.status === 400 && selfReset.json?.code === 'self_reset_forbidden');
  const mustChange = await login(`smoke-analyst-${RUN}@example.test`, pw);
  check('an account flagged for a password change can sign in', mustChange.status === 201 && mustChange.json.user.mustChangePassword === true);
  const blockedByGuard = await call('GET', '/incidents', { token: mustChange.json.accessToken });
  check('and then is refused everything but me/change-password (403, password_change_required)', blockedByGuard.status === 403 && blockedByGuard.json?.code === 'password_change_required', `${blockedByGuard.status} ${blockedByGuard.json?.code}`);
  const meOk = await call('GET', '/auth/me', { token: mustChange.json.accessToken });
  check('me still works for it', meOk.status === 200);
  const reset = await A('POST', `/auth/users/${analyst.json.id}/reset-password`, { body: { newPassword: `Reset-${RUN}-Pass2!` } });
  check('admin reset of another account works and returns nothing sensitive', reset.status === 201 && Object.keys(reset.json).join() === 'ok');
  const oldTokenStillWorks = await call('GET', '/auth/me', { token: mustChange.json.accessToken });
  check('the access token of the reset account keeps working only until it expires (documented limit)', oldTokenStillWorks.status === 200 || oldTokenStillWorks.status === 401);
  const off = await A('PATCH', `/auth/users/${analyst.json.id}`, { body: { isActive: false } });
  check('deactivate an account', off.status === 200 && off.json?.isActive === false);
  const noLogin = await login(`smoke-analyst-${RUN}@example.test`, `Reset-${RUN}-Pass2!`);
  check('a deactivated account cannot sign in', noLogin.status === 401);

  // ---- role checks as a viewer ----
  const v = await login(`smoke-viewer-${RUN}@example.test`, pw); const VT = v.json.accessToken;
  for (const [m, p] of [['GET', '/rules'], ['GET', '/auth/users'], ['GET', '/api-keys'], ['GET', '/audit-logs'], ['GET', '/settings/operational'], ['GET', '/ips'], ['GET', '/events'], ['GET', '/reports/security-summary'], ['GET', '/security/blocks/history']]) {
    const r = await call(m, p, { token: VT }); check(`viewer is refused ${m} ${p}`, r.status === 403, `${r.status}`);
  }
  for (const p of ['/reports/executive-summary', '/incidents', '/security/blocked-ips', '/security/allowlist']) { const r = await call('GET', p, { token: VT }); check(`viewer may read ${p}`, r.status === 200, `${r.status}`); }

  // ---- settings, rules ----
  const st = await A('GET', '/settings/operational'); check('settings 200', st.status === 200);
  shape('settings', st.json, { version: 'string', intelligenceProviders: 'array', autoBlock: 'object', rateLimits: 'object', riskLevels: 'object', sessions: 'object' });
  check('settings contain no secrets', !/secret|pepper|password|DATABASE_URL|mysql:/i.test(JSON.stringify(st.json)));
  const rules = await A('GET', '/rules'); check('rules 200 with 16 rules', rules.status === 200 && rules.json.data.length === 16, `${rules.json?.data?.length}`);
  for (const r of rules.json.data) { shape(`rule ${r.code}`, r, { code: 'string', title: 'string', description: 'string', isEnabled: 'boolean', priority: 'number', config: 'object', defaultConfig: 'object', isDefault: 'boolean', limits: 'object' }); }
  const bf = rules.json.data.find((r) => r.code === 'brute_force_login');
  const bad = await A('PATCH', '/rules/brute_force_login', { body: { config: { threshold: 0 } } }); check('rule: out-of-range value refused (400)', bad.status === 400);
  const win = await A('PATCH', '/rules/brute_force_login', { body: { config: { windowMinutes: 60 } } }); check('rule: fixed window cannot be changed (400)', win.status === 400);
  const unk = await A('PATCH', '/rules/brute_force_login', { body: { config: { nope: 1 } } }); check('rule: unknown setting refused (400)', unk.status === 400);
  const edit = await A('PATCH', '/rules/brute_force_login', { body: { config: { threshold: bf.config.threshold + 1, incidentAt: bf.config.incidentAt + 1 }, reason: `smoke ${RUN}` } });
  check('rule: valid change accepted and stored in full', edit.status === 200 && edit.json.isDefault === false && Object.keys(edit.json.config).length === Object.keys(bf.config).length, `${edit.status}`);
  const reset2 = await A('POST', '/rules/brute_force_login/reset', { body: { reason: `smoke ${RUN} cleanup` } });
  check('rule: reset restores the defaults', reset2.status === 201 && reset2.json.isDefault === true);
  const hist = await A('GET', `/audit-logs?targetType=rule&targetId=brute_force_login&pageSize=10&sortBy=createdAt&sortOrder=desc`);
  check('rule changes are audited with old and new values', hist.status === 200 && hist.json.data.some((a) => a.metadata?.old && a.metadata?.new && a.metadata?.reason?.includes(RUN)));

  // ---- api key, events, incident ----
  const key = await A('POST', '/api-keys', { body: { name: `smoke-${RUN}`, scopes: ['events:write', 'block:read'] } });
  check('create api key', key.status === 201 && /^IRS_/.test(key.json?.apiKey || ''));
  shape('api key created', key.json, { id: 'string', name: 'string', apiKey: 'string', scopes: 'array' });
  const keys = await A('GET', '/api-keys'); check('api keys list 200', keys.status === 200 && T.array(keys.json));
  for (const k of keys.json.slice(0, 3)) { shape('api key row', k, { id: 'string', name: 'string', keyPrefix: 'string', scopes: 'string', isActive: 'boolean' }); check('key list never shows a hash or full key', !('keyHash' in k) && !('apiKey' in k)); }
  const attacker = `198.51.100.${(parseInt(RUN, 36) % 200) + 20}`;
  for (let i = 0; i < 14; i++) await call('POST', '/events', { key: key.json.apiKey, body: { event_type: 'login_failed', severity: 'MEDIUM', ip_address: attacker, request_method: 'POST', request_path: '/login', user_id: `victim${i % 3}`, event_id: `smoke-${RUN}-${i}` } });
  await new Promise((r) => setTimeout(r, 800));
  const list = await A('GET', `/incidents?search=${attacker}&pageSize=5&sortBy=createdAt&sortOrder=desc`);
  check('incident list 200 with paging meta', list.status === 200 && T.array(list.json?.data) && T.object(list.json?.meta));
  shape('incident list meta', list.json.meta, { page: 'number', pageSize: 'number', total: 'number', totalPages: 'number' });
  check('events created an incident for the attacking address', list.json.data.length >= 1, `found ${list.json.data.length}`);
  const inc = list.json.data[0];
  shape('incident row', inc, { id: 'string', incidentId: 'string', title: 'string', severity: 'string', status: 'string', riskScore: 'number', createdAt: 'string', updatedAt: 'string' });
  check('incident row has assignee key (null when unassigned)', 'assignee' in inc);
  const byNo = await A('GET', `/incidents/${inc.incidentId}`); const byId = await A('GET', `/incidents/${inc.id}`);
  check('incident detail by public number AND by id', byNo.status === 200 && byId.status === 200 && byNo.json.id === byId.json.id);
  shape('incident detail', byNo.json, { id: 'string', incidentId: 'string', timeline: 'array', events: 'array' });
  const rep = await A('GET', `/reports/incidents/${inc.incidentId}`); check('incident report 200', rep.status === 200);
  shape('incident report', rep.json, { headline: 'string', severity: 'string', status: 'string', sections: 'object', limitations: 'array', generatedAt: 'string' });
  shape('incident report sections', rep.json.sections, { whatHappened: 'string', whyItMatters: 'string', riskLevel: 'object', evidence: 'array', actionTaken: 'array', currentStatus: 'string', recommendedActions: 'array' });
  const txt = await A('GET', `/reports/incidents/${inc.incidentId}?format=text`, { headers: { Accept: 'text/plain' } }); check('incident report as text', txt.status === 200 && txt.text.length > 50);
  const tech = await A('GET', `/reports/technical/${inc.incidentId}`); check('technical report 200', tech.status === 200);
  shape('technical report', tech.json, { activity: 'object', rulesFired: 'array', blocks: 'array', allowlisted: 'boolean', notes: 'array' });
  const ex = await A('GET', '/reports/executive-summary?days=7'); check('executive summary 200', ex.status === 200);
  shape('executive summary', ex.json, { posture: 'string', headline: 'string', overview: 'string', keyNumbers: 'array', notableIncidents: 'array', needsAttention: 'array', trend: 'string', limitations: 'array', period: 'object' });
  check('posture is one of the four words', ['URGENT', 'ACTION_NEEDED', 'MONITORING', 'ALL_CLEAR'].includes(ex.json.posture));
  const sec = await A('GET', '/reports/security-summary?days=7'); check('security summary 200', sec.status === 200);
  shape('security summary', sec.json, { totals: 'object', trend: 'object', eventsByType: 'array', eventsByRiskLevel: 'array', incidentsBySeverity: 'array', incidentsByStatus: 'array', incidentsByRule: 'array', topSourceIps: 'array', response: 'object', blocking: 'object', daily: 'array', notes: 'array' });
  const exCustom = await A('GET', `/reports/executive-summary?from=${encodeURIComponent(new Date(Date.now() - 86400000).toISOString())}&to=${encodeURIComponent(new Date().toISOString())}`); check('executive summary with a custom range', exCustom.status === 200);

  // incident actions
  const note = await A('POST', `/incidents/${inc.id}/notes`, { body: { note: `smoke note ${RUN}` } });
  check('add a note (timeline entry, status unchanged)', note.status === 201 && note.json.action === 'note.added');
  const afterNote = await A('GET', `/incidents/${inc.id}`); check('note appears on the timeline and status did not change', afterNote.json.timeline.some((t) => t.details?.includes(RUN)) && afterNote.json.status === byId.json.status);
  const asgn = await A('POST', `/incidents/${inc.id}/assign`, { body: { assignedTo: me.json.id } });
  check('assign', asgn.status === 201 || asgn.status === 200, `${asgn.status}`);
  const afterAssign = await A('GET', `/incidents/${inc.id}`);
  check('assignee object carries id, email, name', afterAssign.json.assignee?.id === me.json.id && T.string(afterAssign.json.assignee?.email));
  const stat = await A('POST', `/incidents/${inc.id}/status`, { body: { status: 'INVESTIGATING', notes: `smoke ${RUN}` } });
  check('change status', (stat.status === 201 || stat.status === 200) && stat.json?.status === 'INVESTIGATING', `${stat.status}`);
  const noteEmpty = await A('POST', `/incidents/${inc.id}/notes`, { body: { note: '' } }); check('empty note refused (400)', noteEmpty.status === 400);
  const noteLong = await A('POST', `/incidents/${inc.id}/notes`, { body: { note: 'x'.repeat(2001) } }); check('overlong note refused (400)', noteLong.status === 400);

  // ---- addresses and blocking ----
  const ips = await A('GET', `/ips?search=${attacker.split('.').slice(0, 3).join('.')}&pageSize=5&sortBy=riskScore&sortOrder=desc`);
  check('address list 200', ips.status === 200 && ips.json.data.length >= 1, `${ips.status}`);
  shape('address row', ips.json.data[0], { id: 'string', ipAddress: 'string', riskScore: 'number', riskLevel: 'string', eventCount: 'number', blocked: 'boolean', firstSeenAt: 'string', lastSeenAt: 'string' });
  const badSort = await A('GET', '/ips?sortBy=passwordHash'); check('address list ignores a sort column that is not allowed (no 500)', badSort.status < 500, `${badSort.status}`);
  const wild = await A('GET', "/ips?search=%25_'--"); check('address search with wildcard and quote characters is harmless', wild.status === 200);
  const ipd = await A('GET', `/ips/${attacker}`); check('address detail 200', ipd.status === 200);
  shape('address detail', ipd.json, { ip: 'object', events: 'array', blocks: 'array', isPrivate: 'boolean' });
  const blk = await A('POST', '/security/block', { body: { ipAddress: attacker, reason: `smoke ${RUN}`, ttlMinutes: 15, relatedIncidentId: inc.id } });
  check('block an address', blk.status === 201 || blk.status === 200, `${blk.status} ${JSON.stringify(blk.json)?.slice(0, 80)}`);
  const priv = await A('POST', '/security/block', { body: { ipAddress: '10.0.0.5', reason: 'x' } });
  check('a private address cannot be blocked (400)', priv.status === 400 && /private/i.test(JSON.stringify(priv.json)), `${priv.status}`);
  const active = await A('GET', '/security/blocked-ips'); check('blocked list shape', active.status === 200 && T.array(active.json?.data));
  const mine = active.json.data.find((b) => b.ipAddress === attacker);
  check('the block shows as in force', !!mine); if (mine) shape('active block', mine, { ipAddress: 'string', reason: 'string', permanent: 'boolean', automatic: 'boolean', createdAt: 'string' });
  const listBlocked = await A('GET', `/ips?blocked=true&pageSize=50`); check('address list can filter blocked=true', listBlocked.json.data.some((r) => r.ipAddress === attacker && r.blocked === true));
  const hist2 = await A('GET', `/security/blocks/history?ip=${attacker}&limit=10`); check('block history list', hist2.status === 200 && T.array(hist2.json) && hist2.json.length >= 1);
  shape('block history row', hist2.json[0], { id: 'string', ipAddress: 'string', action: 'string', reason: 'string', automatic: 'boolean', createdAt: 'string' });
  const allow = await A('POST', '/security/allow', { body: { ipAddress: attacker, reason: `smoke ${RUN}`, ttlMinutes: 30 } });
  check('allowlist add', allow.status === 201 || allow.status === 200);
  const blkAllowed = await A('POST', '/security/block', { body: { ipAddress: attacker, reason: 'x' } });
  check('an allowlisted address cannot be blocked (409/400, "allowlist" in the message)', [400, 409].includes(blkAllowed.status) && /allowlist/i.test(JSON.stringify(blkAllowed.json)), `${blkAllowed.status}`);
  const al = await A('GET', '/security/allowlist'); check('allowlist list', al.status === 200 && T.array(al.json));
  shape('allowlist row', al.json.find((a) => a.ipAddress === attacker) ?? {}, { id: 'string', ipAddress: 'string', reason: 'string', createdAt: 'string' });
  const rm = await A('DELETE', `/security/allow/${attacker}`); check('allowlist remove', rm.status === 200 || rm.status === 204);
  const unb = await A('POST', '/security/unblock', { body: { ipAddress: attacker, reason: `smoke ${RUN} cleanup` } }); check('unblock', unb.status === 201 || unb.status === 200, `${unb.status}`);
  const cors = await call('OPTIONS', '/incidents', { headers: { 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' } });
  check('CORS allows the dashboard origin with credentials', cors.headers.get('access-control-allow-origin') === ORIGIN && cors.headers.get('access-control-allow-credentials') === 'true');
  const expose = await call('GET', '/health'); check('CORS exposes Retry-After to the browser', /Retry-After/i.test(expose.headers.get('access-control-expose-headers') || ''));

  // ---- audit ----
  const aud = await A('GET', '/audit-logs?page=1&pageSize=10&sortBy=createdAt&sortOrder=desc'); check('audit log 200', aud.status === 200 && T.array(aud.json?.data));
  shape('audit row', aud.json.data[0], { id: 'string', actorType: 'string', action: 'string', result: 'string', createdAt: 'string' });
  const audF = await A('GET', '/audit-logs?action=block&result=SUCCESS&pageSize=5'); check('audit filters accepted', audF.status === 200);
  const audDates = await A('GET', `/audit-logs?from=${encodeURIComponent(new Date(Date.now() - 3600000).toISOString())}&to=${encodeURIComponent(new Date().toISOString())}`); check('audit date range accepted', audDates.status === 200);

  // ---- errors have the shape the UI relies on ----
  const nf = await A('GET', '/incidents/does-not-exist'); check('unknown incident is 404 with the standard error body', nf.status === 404 && T.string(nf.json?.message) && T.string(nf.json?.timestamp), `${nf.status}`);
  const noAuth = await call('GET', '/incidents'); check('no token is 401', noAuth.status === 401);
  const val = await A('POST', '/security/block', { body: { reason: '' } }); check('validation errors give an array of messages', val.status === 400 && T.array(val.json?.message));

  // ---- clean up ----
  const rev = await A('DELETE', `/api-keys/${key.json.id}`);
  check('revoke the smoke key; response carries no hash', (rev.status === 200 || rev.status === 204) && !JSON.stringify(rev.json ?? {}).includes('keyHash'));
  await A('PATCH', `/auth/users/${viewer.json.id}`, { body: { isActive: false } });
  const out = await (async () => { const cs = await call('GET', '/auth/csrf'); return call('POST', '/auth/logout', { body: {}, headers: { 'X-CSRF-Token': cs.json?.csrfToken ?? 'x' } }); })();
  check('sign out', out.status === 201 || out.status === 200);
  check('sign-out cleared the cookie', !jar.has('ir_rt'));
}

main().catch((e) => { failed++; fails.push(`aborted: ${e.message}`); }).finally(() => {
  console.log(`\nsmoke: ${passed} passed, ${failed} failed`);
  for (const f of fails) console.log(`  FAIL ${f}`);
  process.exit(failed ? 1 : 0);
});
