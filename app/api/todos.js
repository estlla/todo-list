const { route, readUser, writeUser, isCurrent, cleanDue, cleanRemind, MAX_TODOS } = require('./_lib');

module.exports = route(['GET', 'PUT'], async (req, res, { json, me, session, body }) => {
  const rec = await readUser(me);
  if (!isCurrent(rec, session)) return json(401, { error: 'Not signed in.' });

  if (req.method === 'GET') {
    return json(200, { todos: (rec.data.todos || []).map(t => ({ remind: '', reminded: false, ...t })) });
  }

  if (!Array.isArray(body.todos) || body.todos.length > MAX_TODOS) return json(400, { error: 'Invalid todos.' });
  const todos = body.todos.map(t => ({
    text: String(t && t.text).slice(0, 500),
    done: !!(t && t.done),
    due: cleanDue(t && t.due),
    remind: cleanRemind(t && t.remind),
    reminded: !!(t && t.reminded),
  }));
  // Replaces the whole list; the latest save wins.
  await writeUser(me, { ...rec.data, todos });
  return json(200, { ok: true });
}, { auth: true });
