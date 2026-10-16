const crypto = require('crypto');
const { route, readUser, writeUser, hashPassword, setSession, isCurrent } = require('./_lib');

const MAX_FAILURES = 5;          // wrong "current password" guesses, shared with the login lockout
const WINDOW_MS = 15 * 60 * 1000;

module.exports = route(['POST'], async (req, res, { json, me, session, body }) => {
  const current = typeof body.current === 'string' ? body.current : '';
  const next = typeof body.next === 'string' ? body.next : '';
  if (next.length < 8 || next.length > 200) return json(400, { error: 'New password must be 8–200 characters.' });
  if (next === current) return json(400, { error: 'New password must be different from the current one.' });

  const rec = await readUser(me);
  if (!isCurrent(rec, session)) return json(401, { error: 'Not signed in.' });

  const now = Date.now();
  const recent = (rec.data.failures || []).filter(t => t > now - WINDOW_MS);
  if (recent.length >= MAX_FAILURES) return json(429, { error: 'Too many attempts. Try again in 15 minutes.' });

  const attempt = hashPassword(current.slice(0, 200), rec.data.salt);
  const ok = current.length <= 200 && crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(rec.data.hash, 'hex'));
  if (!ok) {
    await writeUser(me, { ...rec.data, failures: [...recent, now] });
    return json(403, { error: 'Current password is incorrect.' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(next, salt);
  await writeUser(me, { ...rec.data, salt, hash, failures: [] });
  setSession(res, me, hash); // keeps this device signed in; every other device is signed out
  return json(200, { ok: true });
}, { auth: true });
