'use strict';
// HTML sections for S3, RDS and CloudFront (numbered by the caller).
const { s3Tables, rdsTables, cfTables, fmtBytes } = require('./svc-text');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cell = (c) => (c && typeof c === 'object' ? `<span class="b ${c.k}">${esc(c.t)}</span>` : esc(c));
const table = ({ head, rows }) => `<table><tr>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr>${rows.map((r) => `<tr>${r.map((c) => `<td>${cell(c)}</td>`).join('')}</tr>`).join('')}</table>`;
const why = (title, text, names) => `<div class="f medium"><b>${esc(title)}</b><p>${esc(text)}</p><p class="meta">Buckets: ${esc(names.slice(0, 40).join(', '))}${names.length > 40 ? ` and ${names.length - 40} more` : ''}</p></div>`;
const failed = (n, t) => `<h2>${n}. ${t}</h2><p class="meta">This review could not be completed. See the scan warnings.</p>`;
const stale = (n, t) => `<h2>${n}. ${t}</h2><p class="meta">This report was created before this check was added. Run a new scan to include it.</p>`;

function renderS3(r, n) {
  if (!r.s3) return stale(n, 'S3 buckets');
  if (r.s3.failed) return failed(n, 'S3 buckets');
  const s = r.s3.summary; const t = s3Tables(r.s3);
  if (!r.s3.buckets.length) return `<h2>${n}. S3 buckets</h2><p>No S3 buckets found.</p>`;
  return `<h2>${n}. S3 buckets</h2>
<div class="cards"><div class="c"><div class="n">${s.buckets}</div><div class="l">Buckets</div></div><div class="c"><div class="n">${esc(fmtBytes(s.totalBytes))}</div><div class="l">Total stored</div></div>
<div class="c"><div class="n">${s.versioningOff}</div><div class="l">No versioning</div></div><div class="c"><div class="n">${s.replicationOff}</div><div class="l">No replication</div></div><div class="c"><div class="n">${s.policyIssues}</div><div class="l">Policy issues</div></div></div>
<p class="meta">Size and object counts come from CloudWatch daily storage metrics (they can be up to two days behind). Storage classes show how the data is split.</p>
${table(t.main)}
<h3>Bucket policy review</h3>
${t.policy.rows.length ? table(t.policy) + (t.policy.more ? `<p class="meta">${t.policy.more} more issue(s) not listed; see the JSON export.</p>` : '') : '<p class="ok-msg">No bucket policy issues found.</p>'}
${t.noVersioning.length ? why('Why versioning should be enabled', t.whyVersioning, t.noVersioning) : '<p class="ok-msg">Versioning is enabled on every bucket.</p>'}
${t.noReplication.length ? why('Why replication should be enabled', t.whyReplication, t.noReplication) : '<p class="ok-msg">Replication is enabled on every bucket.</p>'}`;
}

function renderRds(r, n) {
  if (!r.rds) return stale(n, 'RDS databases');
  if (r.rds.failed) return failed(n, 'RDS databases');
  if (!r.rds.instances.length) return `<h2>${n}. RDS databases</h2><p>No RDS databases found in any region.</p>`;
  const t = rdsTables(r.rds); const s = r.rds.summary;
  return `<h2>${n}. RDS databases</h2>
<div class="cards"><div class="c"><div class="n">${s.instances}</div><div class="l">Databases</div></div><div class="c"><div class="n">${s.pendingUpdates}</div><div class="l">With pending updates</div></div><div class="c"><div class="n">${s.needAttention}</div><div class="l">Need attention</div></div></div>
<p class="meta">CPU, RAM and storage cover the last 7 days (daily average and peak).</p>
${table(t.main)}
<h3>Recommendations and pending updates</h3>
${t.recs.rows.length ? table(t.recs) : '<p class="ok-msg">No recommendations. Every database is healthy and up to date.</p>'}`;
}

function renderCloudFront(r, n) {
  if (!r.cloudfrontService) return stale(n, 'CloudFront');
  if (r.cloudfrontService.failed) return failed(n, 'CloudFront');
  const t = cfTables(r.cloudfrontService);
  return `<h2>${n}. CloudFront</h2>
${r.cloudfrontService.distributions.length ? `<p class="meta">Traffic and error figures cover the last 7 days.</p>${table(t.main)}<h3>Recommendations</h3>${t.recs.rows.length ? table(t.recs) : '<p class="ok-msg">No recommendations.</p>'}` : '<p>No CloudFront distributions found.</p>'}
<h3>What the AMC team should monitor for CloudFront</h3>${table(t.monitor)}`;
}

module.exports = { renderS3, renderRds, renderCloudFront };
