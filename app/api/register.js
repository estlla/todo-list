const crypto = require('crypto');
const { route, writeUser, hashPassword, setSession } = require('./_lib');

module.exports = route(['POST'], async (req, res, { json, body }) => {
  const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return json(400, { error: 'Username must be 3–20 letters, numbers or underscores.' });
  if (password.length < 8 || password.length > 200) return json(400, { error: 'Password must be 8–200 characters.' });

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPassword(password, salt);
  const created = await writeUser(username, { salt, hash, todos: [], failures: [] }, { create: true });
  if (!created) return json(409, { error: 'That username is taken.' });

  setSession(res, username, hash);
  return json(201, { username });
});
