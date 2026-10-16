const { route, readUser } = require('./_lib');

module.exports = route(['GET'], async (req, res, { json, me }) => {
  // Confirm the account still exists (a signed cookie outlives a deleted user).
  if (!(await readUser(me))) return json(401, { error: 'Not signed in.' });
  return json(200, { username: me });
}, { auth: true });
