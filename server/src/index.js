'use strict';
const path = require('path');
const fs = require('fs');
const express = require('express');
const store = require('./store');
const jobs = require('./jobs');
const reports = require('./report');
const { buildDocx } = require('./docx');

const app = express();
app.use(express.json());

const wrap = (fn) => (req, res) => {
  try { fn(req, res); } catch (e) { res.status(e.status || 400).json({ error: e.message }); }
};

/* clients (stored in data/clients.json) */
app.get('/api/clients', wrap((req, res) => res.json(store.list())));
app.post('/api/clients', wrap((req, res) => res.status(201).json(store.create(req.body || {}))));
app.put('/api/clients/:id', wrap((req, res) => res.json(store.update(req.params.id, req.body || {}))));
app.delete('/api/clients/:id', wrap((req, res) => { store.remove(req.params.id); res.status(204).end(); }));

/* scanning */
app.post('/api/scan/all', wrap((req, res) => {
  const clients = store.list().filter((c) => !jobs.running(c.id));
  if (!clients.length) throw new Error('No clients to scan (none registered, or all are already being scanned)');
  res.status(202).json(jobs.startJob(clients));
}));
app.post('/api/scan/:id', wrap((req, res) => {
  const client = store.get(req.params.id);
  if (!client) throw Object.assign(new Error('Client not found'), { status: 404 });
  const existing = jobs.running(client.id);
  if (existing) return res.status(202).json(existing);
  res.status(202).json(jobs.startJob([client]));
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
// Bound to localhost only: this console can trigger scans against client accounts and has no login.
const server = app.listen(PORT, '127.0.0.1', () => console.log(`Infosprint Monitoring running on http://127.0.0.1:${PORT}`));
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\nPort ${PORT} is already in use - an older copy of this app is probably still running.\nStop it (Ctrl+C in its window, or in PowerShell run:\n  Get-NetTCPConnection -LocalPort ${PORT} -State Listen | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }\n) and run npm start again, or use another port: $env:PORT=4100; npm start\n`);
    process.exit(1);
  }
  throw e;
});
