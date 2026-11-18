'use strict';
const path = require('path');
const fs = require('fs');
const express = require('express');
const store = require('./store');
const auth = require('./auth');
const jobs = require('./jobs');
const reports = require('./report');
const { buildDocx } = require('./docx');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback'); // nginx on this machine passes the real client IP and protocol
app.use(express.json({ limit: '100kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  if (req.path.startsWith('/api')) res.setHeader('Cache-Control', 'no-store');
  next();
});

const wrap = (fn) => (req, res) => {
  try { fn(req, res); } catch (e) { res.status(e.status || 400).json({ error: e.message }); }
};

const awrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => res.status(e.status || 400).json({ error: e.message }));

/* sign-in: everything under /api except login/logout/me needs a signed-in user */
app.use('/api', auth.sameOrigin, auth.attach);

app.post('/api/auth/login', awrap(async (req, res) => {
  const { email, password } = req.body || {};
  const user = await auth.login(email, password, req.ip);
  auth.setSessionCookie(req, res, auth.createSession(user.id));
  res.json(user);
}));
app.post('/api/auth/logout', (req, res) => {
  if (req.sessionToken) auth.destroySession(req.sessionToken);
  auth.clearSessionCookie(req, res);
  res.status(204).end();
});
app.get('/api/auth/me', (req, res) => (req.user ? res.json(req.user) : res.status(401).json({ error: 'Not signed in' })));
app.post('/api/auth/change-password', auth.requireAuth, awrap(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const user = await auth.changeOwnPassword(req.user.id, currentPassword, newPassword);
  auth.setSessionCookie(req, res, auth.createSession(user.id)); // other sessions were ended; keep this one signed in
  res.json(user);
}));

app.use('/api', auth.requireAuth);

/* user administration (admins only) */
app.get('/api/users', auth.requireAdmin, wrap((req, res) => res.json(auth.list())));
app.post('/api/users', auth.requireAdmin, awrap(async (req, res) => res.status(201).json(await auth.createUser(req.body || {}))));
app.put('/api/users/:id', auth.requireAdmin, wrap((req, res) => res.json(auth.updateUser(req.params.id, req.body || {}, req.user.id))));
app.post('/api/users/:id/reset-password', auth.requireAdmin, awrap(async (req, res) => res.json(await auth.resetPassword(req.params.id, (req.body || {}).password))));
app.delete('/api/users/:id', auth.requireAdmin, wrap((req, res) => { auth.removeUser(req.params.id, req.user.id); res.status(204).end(); }));

/* clients (stored in data/clients.json) */
app.get('/api/clients', wrap((req, res) => res.json(store.list())));
app.post('/api/clients', wrap((req, res) => res.status(201).json(store.create(req.body || {}))));
app.put('/api/clients/:id', wrap((req, res) => res.json(store.update(req.params.id, req.body || {}))));
app.put('/api/clients/:id/partner', wrap((req, res) => res.json(store.setPartnerType(req.params.id, (req.body || {}).partnerType))));
app.delete('/api/clients/:id', wrap((req, res) => { store.remove(req.params.id); res.status(204).end(); }));

/* AMC console data and logs (AMC partners only) */
const logs = require('./logs');
const amcClient = (id) => {
  const c = store.get(id);
  if (!c) throw Object.assign(new Error('Client not found'), { status: 404 });
  if (c.partnerType !== 'amc') throw Object.assign(new Error('This account is not an AMC partner'), { status: 400 });
  return c;
};
app.get('/api/clients/:id/amc', wrap((req, res) => {
  const c = amcClient(req.params.id);
  const ls = c.lastScan;
  if (!ls || !ls.folder) return res.json({ amc: null, message: 'No scan yet. Run a scan to collect server details.' });
  const p = reports.reportPath(ls.folder, ls.file, 'json');
  if (!p) return res.json({ amc: null, message: 'The latest report file was not found.' });
  const r = JSON.parse(fs.readFileSync(p, 'utf8'));
  res.json({ amc: r.amc || null, scannedAt: r.scan.finishedAt, message: r.amc ? '' : 'The latest scan ran before this account was marked as AMC partner. Run a new scan.' });
}));
app.get('/api/clients/:id/logs/sources', awrap(async (req, res) => {
  const c = amcClient(req.params.id);
  res.json(await logs.listSources(c));
}));
app.post('/api/clients/:id/logs/fetch', wrap((req, res) => {
  const c = amcClient(req.params.id);
  res.status(202).json(logs.publicJob(logs.createJob({ client: c, user: req.user, request: req.body || {} })));
}));
app.get('/api/clients/:id/logs/jobs/:job', wrap((req, res) => {
  amcClient(req.params.id);
  const j = logs.getJob(req.params.job, req.params.id);
  if (!j) throw Object.assign(new Error('Job not found (exports are kept for 24 hours)'), { status: 404 });
  res.json(logs.publicJob(j));
}));
app.post('/api/clients/:id/logs/jobs/:job/cancel', wrap((req, res) => {
  amcClient(req.params.id);
  const j = logs.getJob(req.params.job, req.params.id);
  if (!j) throw Object.assign(new Error('Job not found'), { status: 404 });
  j.cancelled = true;
  res.json(logs.publicJob(j));
}));
app.get('/api/clients/:id/logs/jobs/:job/download', wrap((req, res) => {
  const c = amcClient(req.params.id);
  const j = logs.getJob(req.params.job, req.params.id);
  const p = logs.downloadPath(j);
  if (!p || !fs.existsSync(p)) throw Object.assign(new Error('Export not ready or expired'), { status: 404 });
  logs.audit({ event: 'download', user: req.user.email, client: c.clientName, jobId: j.id, file: j.download });
  res.download(p, j.download);
}));

/* scanning */
// mode (amc | billing) and range (1w | 1m) are chosen in the console every time a scan starts
const scanOptions = (body, allowMode) => {
  const b = body || {};
  const mode = allowMode && ['amc', 'billing'].includes(b.mode) ? b.mode : undefined;
  const range = ['1w', '1m'].includes(b.range) ? b.range : '1w';
  return { mode, range };
};
app.post('/api/scan/all', wrap((req, res) => {
  const clients = store.list().filter((c) => !jobs.running(c.id));
  if (!clients.length) throw new Error('No clients to scan (none registered, or all are already being scanned)');
  res.status(202).json(jobs.startJob(clients, scanOptions(req.body, false)));
}));
app.post('/api/scan/:id', wrap((req, res) => {
  const client = store.get(req.params.id);
  if (!client) throw Object.assign(new Error('Client not found'), { status: 404 });
  const existing = jobs.running(client.id);
  if (existing) return res.status(202).json(existing);
  res.status(202).json(jobs.startJob([client], scanOptions(req.body, true)));
}));
app.get('/api/jobs/:id', wrap((req, res) => {
  const j = jobs.get(req.params.id);
  if (!j) throw Object.assign(new Error('Job not found'), { status: 404 });
  res.json(j);
}));

/* reports */
app.get('/api/reports', wrap((req, res) => res.json(reports.listReports())));
app.get('/api/reports/:folder/:file.html', wrap((req, res) => {
  // Rendered from the saved JSON on every request, so older reports always use the current layout
  const p = reports.reportPath(req.params.folder, req.params.file, 'json');
  if (!p) throw Object.assign(new Error('Report not found'), { status: 404 });
  res.type('html').send(reports.renderHtml(JSON.parse(fs.readFileSync(p, 'utf8'))));
}));
app.get('/api/reports/:folder/:file.json', wrap((req, res) => {
  const p = reports.reportPath(req.params.folder, req.params.file, 'json');
  if (!p) throw Object.assign(new Error('Report not found'), { status: 404 });
  res.download(p, `${req.params.folder}-${req.params.file}.json`);
}));

app.get('/api/reports/:folder/:file.docx', async (req, res) => {
  try {
    const p = reports.reportPath(req.params.folder, req.params.file, 'json');
    if (!p) return res.status(404).json({ error: 'Report not found' });
    const buf = await buildDocx(JSON.parse(fs.readFileSync(p, 'utf8')));
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', `attachment; filename="${req.params.folder}-${req.params.file}.docx"`);
    res.send(buf);
  } catch (e) { res.status(500).json({ error: `Could not build Word document: ${e.message}` }); }
});

/* built React app */
const dist = path.resolve(__dirname, '..', '..', 'client', 'dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.get(/^(?!\/api).*/, (req, res) => res.sendFile(path.join(dist, 'index.html')));
}

const PORT = process.env.PORT || 4000;
// Bound to localhost only (nginx fronts it). All /api routes require a signed-in user.
const server = app.listen(PORT, '127.0.0.1', () => {
  console.log(`Infosprint Monitoring running on http://127.0.0.1:${PORT}`);
  if (!auth.count()) console.warn('No users exist yet, so nobody can sign in. Create the first admin with:  npm run create-admin');
});
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\nPort ${PORT} is already in use - an older copy of this app is probably still running.\nStop it (Ctrl+C in its window, or in PowerShell run:\n  Get-NetTCPConnection -LocalPort ${PORT} -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }\n) and run npm start again, or use another port: $env:PORT=4100; npm start\n`);
    process.exit(1);
  }
  throw e;
});
