const { route, clearSession } = require('./_lib');

module.exports = route(['POST'], async (req, res, { json }) => {
  clearSession(res);
  return json(200, { ok: true });
});
