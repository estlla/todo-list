const crypto = require('crypto');
const { sql, route, hashPassword, setSession } = require('./_lib');

module.exports = route(['POST'], async (req, res, { json, body }) => {
  const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return json(400, { error: 'Username must be 3–20 letters, numbers or underscores.' });
  if (password.length < 8 || password.length > 200) return json(400, { error: 'Password must be 8–200 characters.' });

  const salt = crypto.randomBytes(16).toString('hex');
  const inserted = await sql`
    INSERT INTO users (username, salt, hash) VALUES (${username}, ${salt}, ${hashPassword(password, salt)})
    ON CONFLICT (username) DO NOTHING RETURNING username`;
  if (!inserted.length) return json(409, { error: 'That username is taken.' });

  setSession(res, username);
  return json(201, { username });
});
