'use strict';
const crypto = require('crypto');
const store = require('./store');
const { scanClient } = require('./scanner');
const { saveReport } = require('./report');

const jobs = new Map();

function running(clientId) {
  for (const j of jobs.values()) {
    if (j.status === 'running' && j.items.some((i) => i.clientId === clientId && ['queued', 'running'].includes(i.status))) return j;
  }
  return null;
}

// Each client is scanned with its own role and produces its own separate report.
function startJob(clients) {
  const job = {
    id: crypto.randomUUID(), status: 'running', startedAt: new Date().toISOString(), finishedAt: null,
    items: clients.map((c) => ({ clientId: c.id, clientName: c.clientName, status: 'queued', message: 'Queued', report: null })),
  };
  jobs.set(job.id, job);
  (async () => {
    for (const item of job.items) {
      const client = store.get(item.clientId);
      item.status = 'running';
      try {
        const report = await scanClient(client, (m) => { item.message = m; });
        const saved = saveReport(report);
        item.status = 'done';
        item.message = `${report.summary.totalInstances} instances, ${report.summary.findings.total} findings`;
        item.report = saved;
        store.setLastScan(client.id, { at: report.scan.finishedAt, status: 'OK', ...saved, summary: report.summary });
      } catch (e) {
        item.status = 'failed';
        let msg = e.message || String(e);
        if (client.externalId) msg = msg.split(client.externalId).join('***'); // never echo the External ID
        item.message = msg;
        store.setLastScan(client.id, { at: new Date().toISOString(), status: 'FAILED', error: item.message });
      }
    }
    job.status = 'finished';
    job.finishedAt = new Date().toISOString();
  })();
  return job;
}

module.exports = { startJob, running, get: (id) => jobs.get(id) || null };
