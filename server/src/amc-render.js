'use strict';
// AMC "Server overview" for the HTML report: one table of utilisation and one of health and logging. No charts.
const { ramNote, storageNote } = require('./amc-text');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const B = (t, c) => `<span class="b ${c}">${esc(t)}</span>`;
const pct = (v) => (v === null || v === undefined ? '—' : `${v}%`);
const hint = (t) => `<span class="b warn" style="white-space:normal;display:inline-block">${esc(t)}</span>`;
const logBadge = (s) => ({ ENABLED: B('Enabled', 'ok'), DISABLED: B('Not enabled', 'bad'), NOT_ENABLED: B('Not enabled', 'bad'), NONE: B('Not enabled', 'bad'), PARTIAL: B('Partial', 'warn'), 'N/A': B('No load balancer', 'ok') }[s] || B('Unknown', 'warn'));
const ssmBadge = (s) => ({ ONLINE: B('Online', 'ok'), OFFLINE: B('Offline', 'warn'), NOT_INSTALLED: B('Not installed', 'bad') }[s] || B('Unknown', 'warn'));
const healthText = (i) => {
  if (!i.health.length) return 'Not behind a load balancer or Auto Scaling group';
  return i.health.map((h) => `${esc(h.kind === 'asg' ? 'Auto Scaling' : h.kind === 'classic' ? 'Classic LB' : 'Target group')} ${esc([h.lb, h.group].filter(Boolean).join(' / '))}: ${h.state === 'healthy' ? B('Healthy', 'ok') : B(h.state || 'unknown', h.state === 'unused' ? 'warn' : 'bad')}${h.reason ? ` <span class="meta">${esc(h.reason)}</span>` : ''}`).join('<br>');
};

function renderServerOverview(r) {
  const a = r.amc;
  if (!a || a.failed || !a.instances.length) return '';
  const rows = a.instances.map((i) => {
    const rn = ramNote(i); const sn = storageNote(i);
    return `<tr><td><b>${esc(i.name || i.instanceId)}</b><div class="meta">${esc(i.instanceId)} · ${esc(i.instanceType)}</div></td><td>${esc(i.region)}</td><td>${esc(i.state)}</td>
    <td>${pct(i.cpu?.average)}</td><td>${pct(i.cpu?.peak)}</td>
    ${rn ? `<td colspan="2">${hint(rn)}</td>` : `<td>${pct(i.memory.average)}</td><td>${pct(i.memory.peak)}</td>`}
    <td>${i.storage.provisionedGiB} GiB<div class="meta">${i.storage.volumes.length} EBS volume(s)</div></td>
    ${sn ? `<td colspan="2">${hint(sn)}</td>` : `<td>${i.storage.usedGiB} GiB</td><td>${i.storage.freeGiB} GiB</td>`}</tr>`;
  }).join('');
  const rows2 = a.instances.map((i) => `<tr><td><b>${esc(i.name || i.instanceId)}</b><div class="meta">${esc(i.instanceId)}</div></td><td>${ssmBadge(i.ssm.status)}</td><td>${healthText(i)}</td>
    <td>${logBadge(i.logging.vpcFlowLogs)}</td><td>${logBadge(i.logging.loadBalancerLogs)}</td><td>${logBadge(i.logging.cloudtrail)}</td></tr>`).join('');
  return `<h2>Server overview</h2>
<p class="meta">Last ${a.period.days} days, hourly. CPU comes from CloudWatch; RAM and storage usage need the agents mentioned below.</p>
<table><tr><th>Server</th><th>Region</th><th>State</th><th>CPU avg</th><th>CPU peak</th><th>RAM avg</th><th>RAM peak</th><th>Storage allocated</th><th>Storage utilised</th><th>Storage available</th></tr>${rows}</table>
<h3>Server health and logging</h3>
<table><tr><th>Server</th><th>SSM agent</th><th>Load balancer / target group / Auto Scaling health</th><th>VPC flow logs</th><th>Load balancer logs</th><th>CloudTrail</th></tr>${rows2}</table>`;
}

module.exports = { renderServerOverview };
