const { sql, route, cleanDue, MAX_TODOS } = require('./_lib');

module.exports = route(['GET', 'PUT'], async (req, res, { json, me, body }) => {
  if (req.method === 'GET') {
    const rows = await sql`SELECT text, done, due FROM todos WHERE username = ${me} ORDER BY position`;
    return json(200, { todos: rows });
  }

  if (!Array.isArray(body.todos) || body.todos.length > MAX_TODOS) return json(400, { error: 'Invalid todos.' });
  const todos = body.todos.map(t => ({
    text: String(t && t.text).slice(0, 500),
    done: !!(t && t.done),
    due: cleanDue(t && t.due),
  }));

  // Replace the whole list atomically: both statements run in one transaction.
  await sql.transaction([
    sql`DELETE FROM todos WHERE username = ${me}`,
    sql`INSERT INTO todos (username, text, done, due, position)
        SELECT ${me}, t.text, t.done, t.due, t.pos - 1
        FROM unnest(${todos.map(t => t.text)}::text[], ${todos.map(t => t.done)}::boolean[], ${todos.map(t => t.due)}::text[])
             WITH ORDINALITY AS t(text, done, due, pos)`,
  ]);
  return json(200, { ok: true });
}, { auth: true });
