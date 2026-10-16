const { route, readUser, isCurrent } = require('./_lib');

module.exports = route(['GET'], async (req, res, { json, me, session }) => {
  // The account must still exist, and the cookie must match the current password.
  if (!isCurrent(await readUser(me), session)) return json(401, { error: 'Not signed in.' });
  return json(200, { username: me });
}, { auth: true });
