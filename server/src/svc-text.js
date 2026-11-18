'use strict';
// Table content for the S3, RDS and CloudFront sections, shared by the HTML and Word reports.
// A cell is a string or { t: text, k: 'ok' | 'bad' | 'warn' } (rendered as a coloured badge).
const { WHY_VERSIONING, WHY_REPLICATION } = require('./s3scan');

const fmtBytes = (b) => {
  if (b === null || b === undefined) return 'No data yet';
  if (b < 1024) return `${b} B`;
  const u = ['KB', 'MB', 'GB', 'TB', 'PB']; let v = b / 1024; let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return `${v >= 100 ? Math.round(v) : Math.round(v * 10) / 10} ${u[i]}`;
};
const pct = (v) => (v === null || v === undefined ? '—' : `${v}%`);
const bad = (t) => ({ t, k: 'bad' }); const ok = (t) => ({ t, k: 'ok' }); const warn = (t) => ({ t, k: 'warn' });
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function s3Tables(s3) {
  const buckets = s3.buckets || [];
  const main = {
    head: ['Bucket', 'Region', 'Total size', 'Objects', 'Storage classes', 'Versioning', 'Replication', 'Bucket policy'],
    rows: buckets.map((b) => [
      b.name, b.region || '—', fmtBytes(b.sizeBytes), b.objects === null ? 'No data yet' : b.objects.toLocaleString('en-US'),
      b.classes.filter((c) => c.bytes > 0).map((c) => `${c.storageClass}: ${fmtBytes(c.bytes)}`).join('; ') || (b.sizeBytes === null ? 'No data yet' : 'Empty'),
      b.versioning === 'ENABLED' ? ok('Enabled') : b.versioning === 'SUSPENDED' ? bad('Suspended') : b.versioning === 'UNKNOWN' ? warn('Unknown') : bad('Not enabled'),
      b.replication === 'ENABLED' ? ok('Enabled') : b.replication === 'UNKNOWN' ? warn('Unknown') : bad('Not enabled'),
      !b.policy.present ? 'No policy' : b.policy.issues.length ? (['CRITICAL', 'HIGH'].includes(b.worstPolicy) ? bad : warn)(`${b.policy.issues.length} issue(s)`) : ok('No issues'),
    ]),
  };
  const issues = buckets.flatMap((b) => b.policy.issues.map((i) => ({ bucket: b.name, ...i })))
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const policy = { head: ['Severity', 'Bucket', 'Issue', 'Recommended fix'], rows: issues.slice(0, 80).map((i) => [(i.severity === 'CRITICAL' || i.severity === 'HIGH' ? bad : i.severity === 'MEDIUM' ? warn : ok)(i.severity), i.bucket, i.title, i.recommendation]), more: Math.max(0, issues.length - 80) };
  return {
    main, policy,
    noVersioning: buckets.filter((b) => b.versioning !== 'ENABLED').map((b) => b.name),
    noReplication: buckets.filter((b) => b.replication !== 'ENABLED').map((b) => b.name),
    whyVersioning: WHY_VERSIONING, whyReplication: WHY_REPLICATION,
  };
}

function rdsTables(rds) {
  const list = rds.instances || [];
  const main = {
    head: ['Database', 'Region', 'Engine / class', 'Status', 'CPU avg', 'CPU peak', 'RAM avg', 'RAM peak', 'Storage allocated', 'Storage used', 'Storage available', 'Pending updates'],
    rows: list.map((i) => [
      i.id, i.region, `${i.engine} ${i.engineVersion || ''} · ${i.instanceClass}${i.multiAz ? ' · Multi-AZ' : ''}`,
      i.health === 'HEALTHY' ? ok(i.status) : i.health === 'STOPPED' ? warn(i.status) : bad(i.status),
      pct(i.cpu?.average), pct(i.cpu?.peak), i.ram ? pct(i.ram.average) : 'No data', i.ram ? pct(i.ram.peak) : 'No data',
      i.aurora ? 'Aurora (auto-scales)' : i.storage ? `${i.storage.allocatedGiB} GiB` : '—',
      i.storage && i.storage.usedGiB !== null ? `${i.storage.usedGiB} GiB (${i.storage.usedPercent}%)` : (i.aurora ? 'Managed by Aurora' : 'No data'),
      i.storage && i.storage.freeGiB !== null ? `${Math.max(i.storage.allocatedGiB - i.storage.usedGiB, 0).toFixed(1)} GiB` : (i.aurora ? 'Managed by Aurora' : 'No data'),
      i.pendingActions.length ? warn(`${i.pendingActions.length} pending`) : ok('None'),
    ]),
  };
  const recs = { head: ['Database', 'Recommendation'], rows: list.flatMap((i) => i.recommendations.map((r) => [i.id, r])) };
  return { main, recs };
}

function cfTables(cf) {
  const list = cf.distributions || [];
  const main = {
    head: ['Distribution', 'State', 'Requests (7d)', '5xx peak', '4xx peak', 'Invalidations (7d / running)', 'Logging', 'WAF', 'Alarms', 'Certificate'],
    rows: list.map((d) => [
      `${d.aliases[0] || d.domain} (${d.id})`, d.enabled ? ok(d.status) : warn('Disabled'),
      d.metrics ? d.metrics.requests.toLocaleString('en-US') : 'No data', d.metrics ? pct(d.metrics.errors5xxPeak) : '—', d.metrics ? pct(d.metrics.errors4xxPeak) : '—',
      `${d.invalidations.last7Days} / ${d.invalidations.inProgress}`,
      d.logging === null ? warn('Unknown') : d.logging ? ok('Enabled') : bad('Not enabled'),
      d.webAcl ? ok('Attached') : bad('None'), d.alarms ? ok(`${d.alarms}`) : bad('None'),
      d.certificate ? (d.certificate.daysToExpiry !== null && d.certificate.daysToExpiry < 30 ? bad : ok)(`${d.certificate.daysToExpiry ?? '?'} days left`) : 'Default / none',
    ]),
  };
  const recs = { head: ['Distribution', 'Recommendation'], rows: list.flatMap((d) => d.recommendations.map((r) => [d.aliases[0] || d.domain, r])) };
  const monitor = { head: ['What to monitor', 'Why and what to watch', 'How'], rows: (cf.monitorList || []).map((m) => m) };
  return { main, recs, monitor };
}

module.exports = { s3Tables, rdsTables, cfTables, fmtBytes };
