// Local test harness: runs the api/*.js functions the way Vercel would. Not deployed (see .vercelignore).
process.loadEnvFile('.env.local');
const http = require('http');
const fs = require('fs');
const path = require('path');

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const m = /^\/api\/([a-z]+)$/.exec(url.pathname);
  if (!m || !fs.existsSync(path.join(__dirname, 'api', m[1] + '.js'))) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
  }
  let data = '';
  req.on('data', c => data += c);
  req.on('end', () => {
    try { req.body = data ? JSON.parse(data) : undefined; } catch { req.body = undefined; }
    res.status = code => { res.statusCode = code; return res; };
    res.json = obj => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(obj)); };
    require('./api/' + m[1] + '.js')(req, res);
  });
}).listen(3100, '127.0.0.1', () => console.log('dev harness on http://localhost:3100'));
