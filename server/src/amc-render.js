'use strict';
const { cpuChart, memChart } = require('./charts');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const B = (t, c) => `<span class="b ${c}">${esc(t)}</span>`;
const logBadge = (s) => ({ ENABLED: B('Enabled', 'ok'), DISABLED: B('Not enabled', 'bad'), NOT_ENABLED: B('Not enabled', 'bad'), PARTIAL: B('Partial', 'warn'), NONE: B('Not enabled', 'bad'), 'N/A': B('No load balancer', 'ok'), UNKNOWN: B('Unknown', 'warn') }[s] || B(s, 'warn'));
const healthBadge = (s) => (s === 'healthy' ? B('Healthy', 'ok') : s === 'unused' ? B('Unused', 'warn') : B(s || 'unknown', 'bad'));
const ssmBadge = (s) => ({ ONLINE: B('SSM online', 'ok'), OFFLINE: B('SSM offline', 'warn'), NOT_INSTALLED: B('SSM not installed', 'bad'), UNKNOWN: B('SSM unknown', 'warn') }[s] || B(s, 'warn'));

// Used by both the report and the console: one block per server
function renderServer(i, period) {
  const st = i.storage;
  const vols = st.volumes.map((v) => `<tr><td>${esc(v.volumeId)}</td><td>${esc(v.device)}</td><td>${v.sizeGiB} GiB</td><td>${esc(v.type)}</td><td>${v.encrypted ? 'Yes' : 'No'}</td></tr>`).join('');
  const fs = st.filesystems.map((f) => `<tr><td>${esc(f.name)}</td><td>${f.usedPercent}% used</td></tr>`).join('');
  const health = i.health.length
    ? `<table><tr><th>Type</th><th>Load balancer / group</th><th>State</th><th>Reason</th></tr>${i.health.map((h) => `<tr><td>${h.kind === 'asg' ? 'Auto Scaling' : h.kind === 'classic' ? 'Classic LB' : 'Target group'}</td><td>${esc([h.lb, h.group].filter(Boolean).join(' / '))}</td><td>${healthBadge(h.state)}</td><td>${esc(h.reason || h.description || '')}</td></tr>`).join('')}</table>`
    : '<p class="meta">Not attached to a load balancer or Auto Scaling group.</p>';
  return `<div class="f ${i.recommendations.length ? 'medium' : 'low'}">
<div class="fh"><b>${esc(i.name || i.instanceId)}</b><span class="meta">${esc(i.instanceId)} · ${esc(i.instanceType)} · ${esc(i.platform)} · ${esc(i.region)} · ${esc(i.state)}</span><span class="rg">${ssmBadge(i.ssm.status)}</span></div>
<p>Private IP ${esc(i.privateIp || '—')} · Public IP ${esc(i.publicIp || '—')} · VPC ${esc(i.vpcId || '—')}</p>
<table><tr><th>VPC flow logs</th><th>Load balancer logs</th><th>CloudTrail</th></tr>
<tr><td>${logBadge(i.logging.vpcFlowLogs)}</td><td>${logBadge(i.logging.loadBalancerLogs)}</td><td>${logBadge(i.logging.cloudtrail)}</td></tr></table>
${i.state === 'running' ? `<div style="display:flex;gap:12px;flex-wrap:wrap;margin:10px 0">
<div><div class="meta">CPU, last 8 days${i.cpu ? ` (avg ${i.cpu.average}%, peak ${i.cpu.peak}%)` : ''}</div>${cpuChart(i, period) || '<p class="meta">No CPU data returned.</p>'}</div>
<div><div class="meta">RAM, last 8 days${i.memory ? ` (avg ${i.memory.average}%, peak ${i.memory.peak}%)` : ''}</div>${memChart(i, period) || '<p class="meta">No RAM metrics in CloudWatch.</p>'}</div></div>` : '<p class="meta">Server is not running; no recent metrics.</p>'}
<h4>Storage</h4>
<p>${st.volumes.length} EBS volume(s), ${st.provisionedGiB} GiB provisioned${st.usedGiB !== null ? `, about ${st.usedGiB} GiB used and ${st.freeGiB} GiB free` : ''}.${st.note ? ` <span class="meta">${esc(st.note)}</span>` : ''}</p>
<table><tr><th>Volume</th><th>Device</th><th>Size</th><th>Type</th><th>Encrypted</th></tr>${vols}</table>
${fs ? `<table><tr><th>Filesystem</th><th>Usage</th></tr>${fs}</table>` : ''}
<h4>Load balancer / Auto Scaling health</h4>${health}
${i.recommendations.map((r) => `<p><b>Recommendation:</b> ${esc(r)}</p>`).join('')}
</div>`;
}

function renderAmcSection(r, num) {
  const a = r.amc;
  if (!a) return '';
  if (a.failed) return `<h2>${num}. AMC server details</h2><p class="meta">The AMC checks could not be completed. See the scan warnings.</p>`;
  const s = a.summary;
  return `<h2>${num}. AMC server details</h2>
<div class="cards"><div class="c"><div class="n">${s.servers}</div><div class="l">Servers</div></div>
<div class="c"><div class="n">${s.memoryMissing}</div><div class="l">No RAM metrics</div></div>
<div class="c"><div class="n">${s.ssmMissing}</div><div class="l">No SSM agent</div></div>
<div class="c"><div class="n">${s.unhealthy}</div><div class="l">Unhealthy</div></div>
<div class="c"><div class="n">${s.flowLogsGaps}</div><div class="l">No VPC flow logs</div></div></div>
<p class="meta">Metrics cover ${a.period.days} days at hourly resolution (${esc(a.period.start.slice(0, 10))} to ${esc(a.period.end.slice(0, 10))}). RAM and disk usage come from the CloudWatch agent; they are not available without it.</p>
${a.instances.length ? a.instances.map((i) => renderServer(i, a.period)).join('') : '<p>No servers found.</p>'}`;
}

module.exports = { renderAmcSection, renderServer };
