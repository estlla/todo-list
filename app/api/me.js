const { sql, route } = require('./_lib');

module.exports = route(['GET'], async (req, res, { json, me }) => {
  // Confirm the account still exists (a signed cookie outlives a deleted user).
  const [user] = await sql`SELECT username FROM users WHERE username = ${me}`;
  if (!user) return json(401, { error: 'Not signed in.' });
  return json(200, { username: me });
}, { auth: true });
