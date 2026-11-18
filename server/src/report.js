'use strict';
const fs = require('fs');
const path = require('path');
const { paths } = require('./store');
const { renderAmcSection } = require('./amc-render');
const { NET, byRegion, selectSecurityGroups, capList, AMI_WHY, affected, PREPARED_BY, SERVICES, instanceRecommendation, selectFindings, findingsNote, thresholdLabel, trunc, groupServiceRecs } = require('./guidance');

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'client';
const fmtDate = (d) => (d ? new Date(d).toISOString().slice(0, 10) : '—');

const STATUS_LABEL = {
  ENABLED: ['Enabled', 'ok'], NOT_ENABLED: ['Not enabled', 'bad'], PARTIAL: ['Partial', 'warn'], ERROR: ['Check failed', 'warn'],
  PROTECTED: ['Policy-protected', 'ok'], MANUAL_ONLY: ['Manual only', 'warn'], NONE: ['No backup', 'bad'], UNKNOWN: ['Unknown', 'warn'],
};
const badge = (s) => { const [t, c] = STATUS_LABEL[s] || [s, 'warn']; return `<span class="b ${c}">${esc(t)}</span>`; };

const safeUrl = (u) => (/^https:\/\//.test(u || '') ? esc(u) : '');

function renderFindingsTable(list) {
  const sel = selectFindings(list);
  const note = findingsNote(sel);
  if (!sel.shown.length) {
    return `<p class="ok-msg">No ${esc(thresholdLabel())} findings.</p>${note ? `<p class="meta">${esc(note)}</p>` : ''}`;
  }
  const rows = sel.shown.map((f) => {
    const rec = f.recommendation || {};
    const link = safeUrl(rec.url);
    const af = affected(f, 5);
    const steps = (rec.steps || []).slice(0, 2);
    const meta = [f.type, f.extra?.cve && f.extra.cve !== f.type ? f.extra.cve : ''].filter(Boolean).join(' · ');
    return `<tr><td><span class="sev ${esc(f.severity.toLowerCase())}">${esc(f.severity)}</span></td>
      <td><b>${esc(trunc(f.title, 140))}</b>${meta ? `<div class="meta">${esc(trunc(meta, 120))}</div>` : ''}</td>
      <td class="num">${f.occurrences || 1}</td>
      <td>${esc(af.shown.join(', '))}${af.more ? ` +${af.more} more` : ''}</td>
      <td>${esc(trunc(rec.text, 260))}${link ? ` <a href="${link}" target="_blank" rel="noreferrer">Docs</a>` : ''}${steps.length ? `<ul>${steps.map((x) => `<li>${esc(trunc(x, 160))}</li>`).join('')}</ul>` : ''}</td></tr>`;
  }).join('');
  return `<table class="ft"><tr><th>Severity</th><th>Finding</th><th>Count</th><th>Affected resources</th><th>Recommended remediation</th></tr>${rows}</table>${note ? `<p class="meta">${esc(note)}</p>` : ''}`;
}

function renderBackupSection(r) {
  const rows = r.regions.flatMap((x) => x.instances.map((i) => ({ region: x.region, i })));
  if (!rows.length) return '<h2>1. Backup status and recommendations</h2><p>No EC2 instances found.</p>';
  const needs = rows.some(({ i }) => i.backup.status !== 'PROTECTED');
  const body = rows.map(({ region, i }) => {
    const rec = instanceRecommendation(i);
    return `<tr><td>${esc(region)}</td><td>${esc(i.instanceId)}</td><td>${esc(i.name)}</td><td>${esc(i.state)}</td>
      <td>${badge(i.backup.status)}</td><td>${esc(i.backup.policies.join('; ') || '—')}</td>
      <td>${fmtDate(i.backup.lastSnapshot)}</td><td>${fmtDate(i.backup.lastAmi)}</td>
      <td>${rec ? esc(rec) : '<span class="b ok">No action needed</span>'}</td></tr>`;
  }).join('');
  return `<h2>1. Backup status and recommendations</h2>
    <table><tr><th>Region</th><th>Instance</th><th>Name</th><th>State</th><th>Backup</th><th>Policies</th><th>Last snapshot</th><th>Last AMI</th><th>Recommendation</th></tr>${body}</table>
    ${needs ? `<div class="f high"><b>Why enabling an AMI backup policy is mandatory</b><p>${esc(AMI_WHY)}</p></div>` : '<p class="ok-msg">Every instance is protected by a backup policy.</p>'}`;
}

function renderNetworkSection(r) {
  const n = r.network;
  if (!n) return '<h2>2. Network exposure and logging</h2><p class="meta">This report was created before network checks were added. Run a new scan to include them.</p>';
  const t = n.totals || {};
  const why = (text) => `<div class="f medium"><b>Why this matters</b><p>${esc(text)}</p></div>`;

  // 2.1 security groups
  const sg = selectSecurityGroups(n.securityGroups || []);
  const sgBody = sg.shown.length ? `<table class="ft"><tr><th>Severity</th><th>Region</th><th>Security group</th><th>Ports open to the internet</th><th>In use</th><th>Recommendation</th></tr>${sg.shown.map((x) => `
    <tr><td><span class="sev ${esc(x.severity.toLowerCase())}">${esc(x.severity)}</span></td><td>${esc(x.region)}</td>
    <td><b>${esc(x.groupId)}</b><div class="meta">${esc(x.groupName)} · ${esc(x.vpcId || '')}</div></td>
    <td>${esc(x.ports.join(', '))}</td><td>${x.inUse === null ? '?' : x.inUse ? 'Yes' : 'No'}</td>
    <td>${esc(NET.sg.rec)}</td></tr>`).join('')}</table>` : '<p class="ok-msg">No critical or high-risk ports are open to the internet.</p>';

  // 2.2 VPC flow logs
  const flow = byRegion(n.flowLogs || []);
  const flowBody = flow.length ? `<table><tr><th>Region</th><th>VPCs without full flow logs</th><th>Recommendation</th></tr>${flow.map((g) => `
    <tr><td>${esc(g.region)}</td><td>${g.items.map((v) => `${esc(v.vpcId)}${v.isDefault ? ' (default)' : ''}${v.name ? ` “${esc(v.name)}”` : ''}${v.status === 'PARTIAL' ? ` – ${esc(v.note)}` : ' – no flow logs'}`).join('<br>')}</td>
    <td>${esc(NET.flow.rec)}</td></tr>`).join('')}</table>` : `<p class="ok-msg">Flow logs are enabled on every VPC${t.vpcs != null ? ` (${t.vpcs} checked)` : ''}.</p>`;

  // 2.3 load balancers
  const lbs = capList(n.loadBalancers || []);
  const lbBody = lbs.shown.length ? `<table><tr><th>Region</th><th>Load balancer</th><th>Type</th><th>Scheme</th><th>Recommendation</th></tr>${lbs.shown.map((x) => `
    <tr><td>${esc(x.region)}</td><td><b>${esc(x.name)}</b></td><td>${esc(x.type)}</td><td>${esc(x.scheme || '')}</td><td>${esc(NET.lb.rec)}${x.type === 'Network' ? ' (NLB access logs cover TLS listeners only.)' : ''}</td></tr>`).join('')}</table>${lbs.more ? `<p class="meta">${lbs.more} more not listed; see the JSON export.</p>` : ''}`
    : `<p class="ok-msg">${t.loadBalancers ? `Access logs are enabled on every load balancer (${t.loadBalancers} checked).` : 'No load balancers found.'}</p>`;

  // 2.4 CloudFront
  const cfs = capList(n.cloudfront || []);
  const cfBody = cfs.shown.length ? `<table><tr><th>Distribution</th><th>Domain</th><th>Recommendation</th></tr>${cfs.shown.map((x) => `
    <tr><td><b>${esc(x.id)}</b></td><td>${esc([x.domain, ...(x.aliases || [])].join(', '))}</td><td>${esc(NET.cf.rec)}${x.note ? ` (${esc(x.note)})` : ''}</td></tr>`).join('')}</table>${cfs.more ? `<p class="meta">${cfs.more} more not listed; see the JSON export.</p>` : ''}`
    : `<p class="ok-msg">${t.cloudfrontDistributions ? `Logging is enabled on every active CloudFront distribution (${t.cloudfrontDistributions} checked).` : 'No CloudFront distributions found.'}</p>`;

  return `<h2>2. Network exposure and logging</h2>
    <h3>2.1 Security groups open to the internet${t.securityGroups != null ? ` (${t.securityGroups} checked)` : ''}</h3>${sgBody}${sg.note ? `<p class="meta">${esc(sg.note)}</p>` : ''}${sg.shown.length ? why(NET.sg.why) : ''}
    <h3>2.2 VPC flow logs</h3>${flowBody}${flow.length ? why(NET.flow.why) : ''}
    <h3>2.3 Load balancer access logs</h3>${lbBody}${lbs.shown.length ? why(NET.lb.why) : ''}
    <h3>2.4 CloudFront logging</h3>${cfBody}${cfs.shown.length ? why(NET.cf.why) : ''}`;
}

function renderRecCard(f) {
  return `<div class="f ${f.severity.toLowerCase()}">
      <div class="fh"><span class="sev">${esc(f.severity)}</span><b>${esc(f.title)}</b></div>
      <p><b>Why this matters:</b> ${esc(f.why)}</p>
      <p><b>Recommendation:</b> ${esc(f.recommendation)}</p>
    </div>`;
}

function renderServiceSection(r, [key, name, sub], n) {
  const recs = groupServiceRecs(r.findings, key);
  const list = r.securityFindings?.[key] || [];
  const occ = r.summary.securityFindings?.occurrences?.[key];
  return `<h2>${n}. ${esc(name)}</h2>
    ${recs.length ? recs.map(renderRecCard).join('') : '<p class="ok-msg">Enabled in every region that runs EC2 instances.</p>'}
    ${r.securityFindings ? `<h3>${esc(sub)}: ${esc(thresholdLabel())} (${list.length} unique${occ != null ? `, ${occ} total` : ''} active)</h3>${renderFindingsTable(list)}` : ''}`;
}

function renderHtml(r) {
  const s = r.summary;
  const regionRowsOrdered = r.regions.filter((x) => x.services).map((x) => `
    <tr><td>${esc(x.region)}</td><td>${x.instanceCount}</td>
    <td>${badge(x.services.guardduty.status)}</td><td>${badge(x.services.inspector.status)}</td><td>${badge(x.services.securityhub.status)}</td></tr>`).join('');

  const warnings = r.warnings.length
    ? `<h2>Scan warnings</h2><ul>${r.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : '';

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(r.client.name)} – AWS Security &amp; Backup Report</title>
<style>
body{font-family:Inter,'Segoe UI Variable','Segoe UI',system-ui,Arial,sans-serif;margin:0;background:#f3f5fb;color:#0f172a;-webkit-font-smoothing:antialiased}
.w{max-width:1100px;margin:0 auto;padding:28px}
h1{margin:0 0 4px;font-size:28px;letter-spacing:-.02em}h2{margin-top:34px;border-bottom:2px solid #c7d2fe;padding-bottom:8px;color:#312e81}
.meta{color:#52606d;font-size:14px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}
.c{background:#fff;border-radius:14px;padding:14px 18px;min-width:130px;box-shadow:0 8px 24px -14px #0f172a40;border-top:3px solid #6366f1}
.c .n{font-size:28px;font-weight:700}.c .l{font-size:12px;color:#52606d;text-transform:uppercase}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid #e4e7eb;text-align:left;vertical-align:top}
th{background:#eef0ff;color:#3730a3}
.b{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.ok{background:#d9f5e5;color:#116530}.bad{background:#fde0e0;color:#a31515}.warn{background:#fff1cc;color:#8a5a00}
.f{background:#fff;border-left:5px solid #999;border-radius:6px;padding:12px 16px;margin:12px 0;box-shadow:0 1px 3px #0001}
.f.high{border-color:#d93025}.f.medium{border-color:#f29900}.f.low{border-color:#1a73e8}
.fh{display:flex;gap:10px;align-items:center}.sev{font-size:11px;font-weight:700;background:#eee;padding:2px 8px;border-radius:4px}
.rg{margin-left:auto;color:#52606d;font-size:12px}.f p{margin:6px 0;font-size:14px}
.ok-msg{color:#116530;font-weight:600}h3{margin:22px 0 6px}
.sf{background:#fff;border-left:5px solid #999;border-radius:6px;margin:8px 0;box-shadow:0 1px 3px #0001}.sf summary{cursor:pointer;padding:10px 14px;display:flex;gap:10px;align-items:center;font-size:14px}
.sf.critical{border-color:#7f1d1d}.sf.high{border-color:#d93025}.sf.medium{border-color:#f29900}.sf.low{border-color:#1a73e8}.ft td.num{text-align:center;font-weight:700}.ft ul{margin:4px 0 0 16px;padding:0;font-size:12px;color:#52606d}.ft .sev{display:inline-block}.sev.critical{background:#7f1d1d;color:#fff}.sev.high{background:#d93025;color:#fff}.sev.medium{background:#f29900;color:#fff}.sev.low{background:#1a73e8;color:#fff}
.prep{background:#fff;border-radius:8px;padding:14px 18px;margin:14px 0;box-shadow:0 1px 3px #0001}.prep div{margin:4px 0;font-size:15px}.prep span{display:inline-block;min-width:170px;color:#52606d}h3{margin:22px 0 6px}
.cnt{background:#1f2933;color:#fff;border-radius:10px;padding:1px 8px;font-size:12px;font-weight:700}.sfb{padding:0 16px 12px;font-size:13px}.sfb p{margin:6px 0}.sfb ol{margin:6px 0 0 18px;padding:0}
@media print{body{background:#fff}.f,.c{box-shadow:none;border:1px solid #ddd}}
.nav{margin-bottom:14px}.nav a{color:#1f6feb;text-decoration:none;font-weight:600}\n@media print{.nav{display:none}}\n</style></head><body><div class="w">\n<div class="nav"><a href="/">&larr; Back to console</a></div><script>if(window.self!==window.top)document.querySelector(".nav").style.display="none"</script>
<h1>AWS Security &amp; Backup Report</h1>
<div class="prep">
<div><span>Report prepared by</span><b>${esc(PREPARED_BY)}</b></div>
<div><span>Report prepared for</span><b>${esc(r.client.name)} (${esc(r.client.accountId)})</b></div>
<div><span>Generated</span><b>${esc(String(r.scan.finishedAt).slice(0, 19).replace('T', ' '))} UTC</b></div>
</div>
<div class="cards">
<div class="c"><div class="n">${s.totalInstances}</div><div class="l">EC2 instances</div></div>
<div class="c"><div class="n">${s.regionsWithInstances}/${s.regionsScanned}</div><div class="l">Regions in use</div></div>
<div class="c"><div class="n">${s.instancesProtected}</div><div class="l">Policy-protected</div></div>
<div class="c"><div class="n">${s.instancesWithoutBackup}</div><div class="l">No backup at all</div></div>
<div class="c"><div class="n">${s.findings.high}</div><div class="l">High findings</div></div>
<div class="c"><div class="n">${s.findings.medium}</div><div class="l">Medium findings</div></div>
${s.securityFindings ? `<div class="c"><div class="n">${s.securityFindings.total}</div><div class="l">Unique service findings${s.securityFindings.totalOccurrences ? ` (${s.securityFindings.totalOccurrences} total)` : ''}</div></div>` : ''}
</div>
${renderBackupSection(r)}
${renderNetworkSection(r)}
${r.amc ? renderAmcSection(r, 3) : ''}
${SERVICES.map((svc, idx) => renderServiceSection(r, svc, idx + 3 + (r.amc ? 1 : 0))).join('')}
<h2>Appendix: security services by region (regions with EC2 instances)</h2>
<table><tr><th>Region</th><th>Instances</th><th>GuardDuty</th><th>Inspector</th><th>Security Hub</th></tr>${regionRowsOrdered || '<tr><td colspan="5">No EC2 instances found.</td></tr>'}</table>
${warnings}
<p class="meta" style="margin-top:32px">Backup policy = AWS Backup plan or Data Lifecycle Manager (DLM) policy covering the instance or its volumes. "Manual only" means snapshots/AMIs exist but no policy automates them.</p>
</div></body></html>`;
}

function saveReport(report) {
  const folder = `${slug(report.client.name)}-${report.client.accountId}`;
  const dir = path.join(paths.REPORTS_DIR, folder);
  fs.mkdirSync(dir, { recursive: true });
  const base = report.scan.finishedAt.replace(/[:.]/g, '-');
  fs.writeFileSync(path.join(dir, `${base}.json`), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(dir, `${base}.html`), renderHtml(report));
  return { folder, file: base };
}

function listReports() {
  if (!fs.existsSync(paths.REPORTS_DIR)) return [];
  const out = [];
  for (const folder of fs.readdirSync(paths.REPORTS_DIR)) {
    const dir = path.join(paths.REPORTS_DIR, folder);
    if (!fs.statSync(dir).isDirectory()) continue;
    for (const f of fs.readdirSync(dir)) {
      if (!f.endsWith('.json')) continue;
      try {
        const r = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
        out.push({ folder, file: f.replace(/\.json$/, ''), clientName: r.client.name, accountId: r.client.accountId, generatedAt: r.scan.finishedAt, summary: r.summary });
      } catch { /* skip unreadable */ }
    }
  }
  return out.sort((a, b) => b.generatedAt.localeCompare(a.generatedAt));
}

function reportPath(folder, file, ext) {
  if (!/^[\w.-]+$/.test(folder) || !/^[\w.-]+$/.test(file)) return null;
  const p = path.join(paths.REPORTS_DIR, folder, `${file}.${ext}`);
  return fs.existsSync(p) ? p : null;
}

module.exports = { renderHtml, saveReport, listReports, reportPath };
