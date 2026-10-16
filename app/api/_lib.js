// Shared helpers for the API functions. Files starting with "_" are not exposed as routes.
//
// Storage: Neon Postgres (connection string in DATABASE_URL), tables created on first use.
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

const SESSION_TTL_S = 7 * 24 * 3600;
const MAX_TODOS = 1000;

const sql = process.env.DATABASE_URL ? neon(process.env.DATABASE_URL) : null;

let schemaReady;
function ensureSchema() {
  schemaReady ??= sql.transaction([
    sql`CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          salt     TEXT NOT NULL,
          hash     TEXT NOT NULL
        )`,
    sql`CREATE TABLE IF NOT EXISTS todos (
          id       BIGSERIAL PRIMARY KEY,
          username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
          text     TEXT NOT NULL,
          done     BOOLEAN NOT NULL DEFAULT FALSE,
          due      TEXT NOT NULL DEFAULT '',
          position INTEGER NOT NULL
        )`,
    sql`CREATE INDEX IF NOT EXISTS todos_user ON todos(username, position)`,
    sql`CREATE TABLE IF NOT EXISTS login_failures (
          username TEXT NOT NULL,
          at       TIMESTAMPTZ NOT NULL DEFAULT now()
        )`,
  ]).catch(e => { schemaReady = undefined; throw e; });
  return schemaReady;
}

const hashPassword = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');

// ---- stateless sessions: base64url(payload).HMAC, so no server memory is needed ----
const b64 = s => Buffer.from(s).toString('base64url');
const mac = payload => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(payload).digest('base64url');

function makeToken(username) {
  const payload = b64(JSON.stringify({ u: username, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_S }));
  return `${payload}.${mac(payload)}`;
}

function readToken(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [payload, sig] = decodeURIComponent(m[1]).split('.');
  if (!payload || !sig) return null;
  const good = Buffer.from(mac(payload));
  const given = Buffer.from(sig);
  if (good.length !== given.length || !crypto.timingSafeEqual(good, given)) return null;
  try {
    const { u, exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return exp > Date.now() / 1000 ? u : null;
  } catch { return null; }
}

// Secure cookies are dropped by browsers on plain http://localhost, so omit the flag in local testing.
const cookie = (value, maxAge) =>
  `sid=${value}; HttpOnly; ${process.env.INSECURE_COOKIES ? '' : 'Secure; '}SameSite=Strict; Path=/; Max-Age=${maxAge}`;
const setSession = (res, username) => res.setHeader('Set-Cookie', cookie(makeToken(username), SESSION_TTL_S));
const clearSession = res => res.setHeader('Set-Cookie', cookie('', 0));

const cleanDue = d => (typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : '');

// Wraps a handler: method check, JSON-only writes, error handling, no caching.
function route(methods, handler, { auth = false } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const json = (status, body) => res.status(status).json(body);
    try {
      if (!methods.includes(req.method)) return json(405, { error: 'Method not allowed.' });
      if (req.method !== 'GET' && !(req.headers['content-type'] || '').startsWith('application/json')) {
        return json(415, { error: 'JSON only.' });
      }
      if (!sql || !process.env.SESSION_SECRET) return json(500, { error: 'Server is not configured.' });
      await ensureSchema();
      let me = null;
      if (auth) {
        me = readToken(req);
        if (!me) return json(401, { error: 'Not signed in.' });
      }
      return await handler(req, res, { json, me, body: req.body && typeof req.body === 'object' ? req.body : {} });
    } catch (e) {
      console.error(e);
      return json(500, { error: 'Something went wrong.' });
    }
  };
}

module.exports = { sql, route, hashPassword, setSession, clearSession, cleanDue, MAX_TODOS };
