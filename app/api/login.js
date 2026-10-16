const crypto = require('crypto');
const { sql, route, hashPassword, setSession } = require('./_lib');

const MAX_FAILURES = 5; // per username per 15 minutes

module.exports = route(['POST'], async (req, res, { json, body }) => {
  const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!/^[a-z0-9_]{3,20}$/.test(username) || !password || password.length > 200) {
    return json(401, { error: 'Invalid username or password.' });
  }

  const [{ n }] = await sql`
    SELECT count(*)::int AS n FROM login_failures WHERE username = ${username} AND at > now() - interval '15 minutes'`;
  if (n >= MAX_FAILURES) return json(429, { error: 'Too many attempts. Try again in 15 minutes.' });

  const [user] = await sql`SELECT salt, hash FROM users WHERE username = ${username}`;
  // Always hash so timing doesn't reveal whether the username exists.
  const attempt = hashPassword(password, user ? user.salt : 'x'.repeat(32));
  const ok = user && crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(user.hash, 'hex'));
  if (!ok) {
    await sql`INSERT INTO login_failures (username) VALUES (${username})`;
    return json(401, { error: 'Invalid username or password.' });
  }

  await sql`DELETE FROM login_failures WHERE username = ${username} OR at < now() - interval '1 day'`;
  setSession(res, username);
  return json(200, { username });
});
