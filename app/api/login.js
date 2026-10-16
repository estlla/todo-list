const crypto = require('crypto');
const { route, readUser, writeUser, hashPassword, setSession } = require('./_lib');

const MAX_FAILURES = 5;          // per username...
const WINDOW_MS = 15 * 60 * 1000; // ...per 15 minutes

module.exports = route(['POST'], async (req, res, { json, body }) => {
  const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!/^[a-z0-9_]{3,20}$/.test(username) || !password || password.length > 200) {
    return json(401, { error: 'Invalid username or password.' });
  }

  const rec = await readUser(username);
  const now = Date.now();
  const recent = rec ? (rec.data.failures || []).filter(t => t > now - WINDOW_MS) : [];
  if (recent.length >= MAX_FAILURES) return json(429, { error: 'Too many attempts. Try again in 15 minutes.' });

  // Always hash so timing doesn't reveal whether the username exists.
  const attempt = hashPassword(password, rec ? rec.data.salt : 'x'.repeat(32));
  const ok = rec && crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(rec.data.hash, 'hex'));
  if (!ok) {
    if (rec) await writeUser(username, { ...rec.data, failures: [...recent, now] });
    return json(401, { error: 'Invalid username or password.' });
  }

  if ((rec.data.failures || []).length) await writeUser(username, { ...rec.data, failures: [] });
  setSession(res, username);
  return json(200, { username });
});
