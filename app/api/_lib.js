// Shared helpers for the API functions. Files starting with "_" are not exposed as routes.
//
// Storage: a private Vercel Blob store, one JSON file per user at users/<username>.json:
//   { salt, hash, todos: [{text, done, due, remind, reminded}], failures: [<ms timestamps of recent bad logins>] }
const crypto = require('crypto');
const { put, get } = require('@vercel/blob');

const SESSION_TTL_S = 7 * 24 * 3600;
const MAX_TODOS = 1000;

// ---- user storage ----
const userPath = username => `users/${username}.json`;

async function readUser(username) {
  const r = await get(userPath(username), { access: 'private', useCache: false });
  if (!r || r.statusCode !== 200) return null;
  return { data: JSON.parse(await new Response(r.stream).text()), etag: r.blob.etag };
}

// create=true fails (returns false) if the user already exists, which makes sign-up atomic.
async function writeUser(username, data, { create = false } = {}) {
  try {
    await put(userPath(username), JSON.stringify(data), {
      access: 'private', contentType: 'application/json',
      addRandomSuffix: false, allowOverwrite: !create, cacheControlMaxAge: 60,
    });
    return true;
  } catch (e) {
    if (create && /already exists/i.test(String(e && e.message))) return false;
    throw e;
  }
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
const cleanRemind = d => (typeof d === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(d) ? d : '');

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
      if (!process.env.BLOB_READ_WRITE_TOKEN || !process.env.SESSION_SECRET) return json(500, { error: 'Server is not configured.' });
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

module.exports = { route, readUser, writeUser, hashPassword, setSession, clearSession, cleanDue, cleanRemind, MAX_TODOS };
