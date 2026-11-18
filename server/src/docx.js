'use strict';
// Builds the Word (.docx) version of a scan report (compact: mandatory findings only).
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType, ShadingType,
  ExternalHyperlink, PageOrientation, Footer, PageNumber, AlignmentType,
} = require('docx');
const {
  NET, byRegion, selectSecurityGroups, capList, AMI_WHY, affected, PREPARED_BY, SERVICES, instanceRecommendation, selectFindings, findingsNote, thresholdLabel, trunc, groupServiceRecs,
} = require('./guidance');

const { cpuChart, memChart } = require('./charts');
let Resvg = null;
try { ({ Resvg } = require('@resvg/resvg-js')); } catch { Resvg = null; } // charts are skipped when the renderer is unavailable
const { ImageRun } = require('docx');

const SEV_COLOR = { CRITICAL: '7F1D1D', HIGH: 'D93025', MEDIUM: 'B06A00', LOW: '1A73E8', INFORMATIONAL: '52606D' };
const STATUS = {
  ENABLED: ['Enabled', '116530'], NOT_ENABLED: ['Not enabled', 'A31515'], PARTIAL: ['Partial', '8A5A00'], ERROR: ['Check failed', '8A5A00'],
  PROTECTED: ['Policy-protected', '116530'], MANUAL_ONLY: ['Manual only', '8A5A00'], NONE: ['No backup', 'A31515'], UNKNOWN: ['Unknown', '8A5A00'],
};
const PAGE_W = 14838; // usable width in twips on landscape A4 with 1000 margins
const FONT = 'Calibri';

const clean = (v) => String(v ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
const run = (t, o = {}) => new TextRun({ text: clean(t), font: FONT, ...o });
const para = (children, o = {}) => new Paragraph({ children: Array.isArray(children) ? children : [run(children)], spacing: { after: 100 }, ...o });
const fmtDate = (d) => (d ? new Date(d).toISOString().slice(0, 10) : '—');
const small = (t, o = {}) => new Paragraph({ children: [run(t, { size: 18, ...o })], spacing: { after: 20 } });
const statusPara = (s) => { const [t, c] = STATUS[s] || [s, '333333']; return new Paragraph({ children: [run(t, { size: 18, bold: true, color: c })] }); };

// cell content: string | Paragraph | Paragraph[]
function cell(content, width, header) {
  let children;
  if (Array.isArray(content)) children = content;
  else if (content instanceof Paragraph) children = [content];
  else children = [new Paragraph({ children: [run(content, { size: 18, bold: header })] })];
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: header ? { type: ShadingType.CLEAR, fill: 'EEF1F5', color: 'auto' } : undefined,
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children,
  });
}

function table(headers, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, widths[i], true)) }),
      ...rows.map((r) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, widths[i], false)) })),
    ],
  });
}

const h1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [run(t, { bold: true, size: 30 })], spacing: { before: 320, after: 120 }, keepNext: true });
const h2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [run(t, { bold: true, size: 22 })], spacing: { before: 200, after: 80 }, keepNext: true });

function link(url, label) {
  if (!/^https:\/\//.test(url || '')) return null;
  return new ExternalHyperlink({ link: url, children: [new TextRun({ text: label, style: 'Hyperlink', font: FONT, size: 18 })] });
}

// "Service not enabled" recommendation (one per service problem, all regions listed)
function recBlock(f) {
  return [
    new Paragraph({ keepNext: true, spacing: { before: 120, after: 40 }, children: [run(`[${f.severity}] `, { bold: true, color: SEV_COLOR[f.severity] || '333333' }), run(f.title, { bold: true })] }),
    para([run('Why this matters: ', { bold: true, size: 20 }), run(f.why, { size: 20 })], { spacing: { after: 40 } }),
    para([run('Recommendation: ', { bold: true, size: 20 }), run(f.recommendation, { size: 20 })]),
  ];
}

function findingsTable(list) {
  const sel = selectFindings(list);
  const note = findingsNote(sel);
  const out = [];
  if (!sel.shown.length) {
    out.push(para([run(`No ${thresholdLabel()} findings.`, { bold: true, color: '116530' })]));
  } else {
    const rows = sel.shown.map((f) => {
      const rec = f.recommendation || {};
      const af = affected(f, 5);
      const l = link(rec.url, 'Docs');
      const meta = [f.type, f.extra?.cve && f.extra.cve !== f.type ? f.extra.cve : ''].filter(Boolean).join(' · ');
      return [
        new Paragraph({ children: [run(f.severity, { size: 18, bold: true, color: SEV_COLOR[f.severity] || '333333' })] }),
        [small(trunc(f.title, 140), { bold: true }), ...(meta ? [small(trunc(meta, 120), { size: 16, color: '52606D' })] : [])],
        new Paragraph({ alignment: AlignmentType.CENTER, children: [run(String(f.occurrences || 1), { size: 18, bold: true })] }),
        `${af.shown.join(', ')}${af.more ? ` +${af.more} more` : ''}`,
        [
          new Paragraph({ children: [run(trunc(rec.text, 260), { size: 18 }), ...(l ? [run(' '), l] : [])], spacing: { after: 20 } }),
          ...(rec.steps || []).slice(0, 2).map((x) => small(`•  ${trunc(x, 160)}`, { size: 16, color: '52606D' })),
        ],
      ];
    });
    out.push(table(['Severity', 'Finding', 'Count', 'Affected resources', 'Recommended remediation'], rows, [1100, 3900, 800, 3100, 5938]));
  }
  if (note) out.push(para([run(note, { size: 18, color: '52606D' })], { spacing: { before: 60 } }));
  return out;
}

function networkSection(r) {
  const out = [h1('2. Network exposure and logging')];
  const n = r.network;
  if (!n) { out.push(para('This report was created before network checks were added. Run a new scan to include them.')); return out; }
  const t = n.totals || {};
  const ok = (m) => para([run(m, { bold: true, color: '116530' })]);
  const why = (m) => para([run('Why this matters: ', { bold: true, size: 20 }), run(m, { size: 20 })], { spacing: { before: 80 } });
  const sevPara = (sv) => new Paragraph({ children: [run(sv, { size: 18, bold: true, color: SEV_COLOR[sv] || '333333' })] });

  const sg = selectSecurityGroups(n.securityGroups || []);
  out.push(h2(`2.1 Security groups open to the internet${t.securityGroups != null ? ` (${t.securityGroups} checked)` : ''}`));
  if (sg.shown.length) {
    out.push(table(['Severity', 'Region', 'Security group', 'Ports open to the internet', 'In use', 'Recommendation'],
      sg.shown.map((x) => [sevPara(x.severity), x.region, `${x.groupId} (${x.groupName}) ${x.vpcId || ''}`, x.ports.join(', '), x.inUse === null ? '?' : x.inUse ? 'Yes' : 'No', NET.sg.rec]),
      [1100, 1200, 3000, 2800, 700, 6038]));
    out.push(why(NET.sg.why));
  } else out.push(ok('No critical or high-risk ports are open to the internet.'));
  if (sg.note) out.push(small(sg.note, { color: '52606D' }));

  const flow = byRegion(n.flowLogs || []);
  out.push(h2('2.2 VPC flow logs'));
  if (flow.length) {
    out.push(table(['Region', 'VPCs without full flow logs', 'Recommendation'],
      flow.map((g) => [g.region, g.items.map((v) => `${v.vpcId}${v.isDefault ? ' (default)' : ''}${v.name ? ` "${v.name}"` : ''} - ${v.status === 'PARTIAL' ? v.note : 'no flow logs'}`).join('\n'), NET.flow.rec]),
      [1800, 6000, 7038]));
    out.push(why(NET.flow.why));
  } else out.push(ok(`Flow logs are enabled on every VPC${t.vpcs != null ? ` (${t.vpcs} checked)` : ''}.`));

  const lbs = capList(n.loadBalancers || []);
  out.push(h2('2.3 Load balancer access logs'));
  if (lbs.shown.length) {
    out.push(table(['Region', 'Load balancer', 'Type', 'Scheme', 'Recommendation'],
      lbs.shown.map((x) => [x.region, x.name, x.type, x.scheme || '', NET.lb.rec]), [1500, 3500, 1300, 1500, 7038]));
    if (lbs.more) out.push(small(`${lbs.more} more not listed; see the JSON export.`, { color: '52606D' }));
    out.push(why(NET.lb.why));
  } else out.push(ok(t.loadBalancers ? `Access logs are enabled on every load balancer (${t.loadBalancers} checked).` : 'No load balancers found.'));

  const cfs = capList(n.cloudfront || []);
  out.push(h2('2.4 CloudFront logging'));
  if (cfs.shown.length) {
    out.push(table(['Distribution', 'Domain', 'Recommendation'],
      cfs.shown.map((x) => [x.id, [x.domain, ...(x.aliases || [])].join(', '), NET.cf.rec + (x.note ? ` (${x.note})` : '')]), [2200, 5000, 7638]));
    if (cfs.more) out.push(small(`${cfs.more} more not listed; see the JSON export.`, { color: '52606D' }));
    out.push(why(NET.cf.why));
  } else out.push(ok(t.cloudfrontDistributions ? `Logging is enabled on every active CloudFront distribution (${t.cloudfrontDistributions} checked).` : 'No CloudFront distributions found.'));
  return out;
}

function chartImage(svg) {
  if (!Resvg || !svg) return null;
  try {
    const png = new Resvg(svg.replace('width="100%"', 'width="520"'), { fitTo: { mode: 'width', value: 1040 }, font: { loadSystemFonts: true } }).render().asPng();
    return new Paragraph({ children: [new ImageRun({ type: 'png', data: png, transformation: { width: 440, height: 145 } })], spacing: { after: 80 } });
  } catch { return null; }
}

function amcSection(r, num) {
  const a = r.amc;
  const out = [h1(`${num}. AMC server details`)];
  if (a.failed) { out.push(para('The AMC checks could not be completed. See the scan warnings.')); return out; }
  const lg = (s) => ({ ENABLED: 'Enabled', DISABLED: 'Not enabled', NOT_ENABLED: 'Not enabled', PARTIAL: 'Partial', NONE: 'Not enabled', 'N/A': 'No load balancer', UNKNOWN: 'Unknown' }[s] || s);
  out.push(para(`Metrics cover the last ${a.period.days} days at hourly resolution. RAM and in-server disk usage need the CloudWatch agent on the server.`));
  if (!a.instances.length) { out.push(para('No servers found.')); return out; }
  const nr = (v, f) => (v === null || v === undefined ? 'Not reported' : f(v));
  out.push(table(['Server', 'Region', 'State', 'CPU avg', 'CPU peak', 'RAM avg', 'RAM peak', 'EBS volumes', 'Storage assigned', 'Storage utilised', 'Storage available', 'SSM agent', 'VPC flow logs', 'LB logs', 'CloudTrail'],
    a.instances.map((i) => [`${i.name || ''} ${i.instanceId}`.trim(), i.region, i.state,
      nr(i.cpu?.average, (v) => `${v}%`), nr(i.cpu?.peak, (v) => `${v}%`), nr(i.memory?.average, (v) => `${v}%`), nr(i.memory?.peak, (v) => `${v}%`),
      String(i.storage.volumes.length), `${i.storage.provisionedGiB} GiB`, nr(i.storage.usedGiB, (v) => `${v} GiB`), nr(i.storage.freeGiB, (v) => `${v} GiB`),
      i.ssm.status.replace('_', ' ').toLowerCase(), lg(i.logging.vpcFlowLogs), lg(i.logging.loadBalancerLogs), lg(i.logging.cloudtrail)]),
    [1900, 800, 700, 700, 700, 700, 700, 650, 900, 900, 900, 850, 850, 800, 900]));
  out.push(h2(`${num}.1 Load balancer, target group and Auto Scaling health`));
  const hrows = a.instances.flatMap((i) => i.health.map((h) => [i.instanceId, h.kind === 'asg' ? 'Auto Scaling' : h.kind === 'classic' ? 'Classic LB' : 'Target group', [h.lb, h.group].filter(Boolean).join(' / '), h.state || 'unknown', h.reason || h.description || '']));
  out.push(hrows.length ? table(['Server', 'Type', 'Load balancer / group', 'State', 'Reason'], hrows, [2400, 1600, 4200, 1400, 5238]) : para('No server is attached to a load balancer or Auto Scaling group.'));
  out.push(h2(`${num}.2 Recommendations`));
  const recs = a.instances.flatMap((i) => i.recommendations.map((x) => [i.name || i.instanceId, x]));
  out.push(recs.length ? table(['Server', 'Recommendation'], recs, [3000, 11838]) : para([run('No monitoring gaps found.', { bold: true, color: '116530' })]));
  out.push(h2(`${num}.3 CPU and RAM, last ${a.period.days} days`));
  let drawn = false;
  for (const i of a.instances.filter((x) => x.state === 'running').slice(0, 25)) {
    const c = chartImage(cpuChart(i, a.period)); const m = chartImage(memChart(i, a.period));
    if (!c && !m) continue;
    drawn = true;
    out.push(para([run(`${i.name || ''} ${i.instanceId}`.trim(), { bold: true })]));
    if (c) out.push(c);
    if (m) out.push(m);
  }
  if (!drawn) out.push(para('Charts are available in the console report; the table above lists the average and peak values.'));
  return out;
}

async function buildDocx(r) {
  const s = r.summary;
  const sc = s.securityFindings;
  const body = [];

  body.push(new Paragraph({ children: [run('AWS Security & Backup Report', { bold: true, size: 44 })], spacing: { after: 120 } }));
  body.push(para([run('Report prepared by: ', { bold: true, size: 24 }), run(PREPARED_BY, { size: 24 })], { spacing: { after: 40 } }));
  body.push(para([run('Report prepared for: ', { bold: true, size: 24 }), run(`${r.client.name} (${r.client.accountId})`, { size: 24 })], { spacing: { after: 40 } }));
  body.push(para([run(`Generated ${String(r.scan.finishedAt).slice(0, 19).replace('T', ' ')} UTC`, { size: 20, color: '52606D' })]));

  body.push(h1('Summary'));
  body.push(table(['Metric', 'Value'], [
    ['EC2 instances', String(s.totalInstances)],
    ['Regions with EC2 instances', `${s.regionsWithInstances} of ${s.regionsScanned} enabled regions`],
    ['Instances protected by a backup policy', String(s.instancesProtected)],
    ['Instances with no backup at all', String(s.instancesWithoutBackup)],
    ...(sc ? [['Unique service findings', `${sc.total} unique (${sc.totalOccurrences ?? sc.total} total occurrences): GuardDuty ${sc.guardduty}, Inspector ${sc.inspector}, Security Hub ${sc.securityhub}; critical ${sc.critical}, high ${sc.high}, medium ${sc.medium}, low ${sc.low}`]] : []),
  ], [5000, PAGE_W - 5000]));

  /* 1. Backup */
  body.push(h1('1. Backup status and recommendations'));
  const inst = r.regions.flatMap((x) => x.instances.map((i) => ({ region: x.region, i })));
  if (inst.length) {
    body.push(table(
      ['Region', 'Instance', 'Name', 'State', 'Backup', 'Policies', 'Last snapshot', 'Last AMI', 'Recommendation'],
      inst.map(({ region, i }) => {
        const rec = instanceRecommendation(i);
        return [region, i.instanceId, i.name || '—', i.state || '', statusPara(i.backup.status), i.backup.policies.join('; ') || '—',
          fmtDate(i.backup.lastSnapshot), fmtDate(i.backup.lastAmi), rec || new Paragraph({ children: [run('No action needed', { size: 18, bold: true, color: '116530' })] })];
      }),
      [1200, 1900, 1500, 900, 1500, 2300, 1200, 1200, 3138],
    ));
    if (inst.some(({ i }) => i.backup.status !== 'PROTECTED')) {
      body.push(h2('Why enabling an AMI backup policy is mandatory'));
      body.push(para([run(AMI_WHY, { size: 20 })]));
    } else {
      body.push(para([run('Every instance is protected by a backup policy.', { bold: true, color: '116530' })], { spacing: { before: 80 } }));
    }
  } else {
    body.push(para('No EC2 instances found.'));
  }

  /* AMC server details, then GuardDuty, Inspector and Security Hub last */
  body.push(...networkSection(r));

  if (r.amc) body.push(...amcSection(r, 3));

  SERVICES.forEach(([key, name, sub], idx) => {
    body.push(h1(`${idx + 3 + (r.amc ? 1 : 0)}. ${name}`));
    const recs = groupServiceRecs(r.findings, key);
    if (recs.length) recs.forEach((f) => body.push(...recBlock(f)));
    else body.push(para([run('Enabled in every region that runs EC2 instances.', { bold: true, color: '116530' })]));
    if (r.securityFindings) {
      const list = r.securityFindings[key] || [];
      const occ = sc?.occurrences?.[key];
      body.push(h2(`${sub}: ${thresholdLabel()} (${list.length} unique${occ != null ? `, ${occ} total` : ''} active)`));
      body.push(...findingsTable(list));
    }
  });

  /* Appendix */
  body.push(h1('Appendix: security services by region'));
  const regionRows = r.regions.filter((x) => x.services).map((x) => [
    x.region, String(x.instanceCount), statusPara(x.services.guardduty.status), statusPara(x.services.inspector.status), statusPara(x.services.securityhub.status),
  ]);
  body.push(regionRows.length
    ? table(['Region', 'Instances', 'GuardDuty', 'Inspector', 'Security Hub'], regionRows, [3000, 1800, 3346, 3346, 3346])
    : para('No EC2 instances found.'));

  if (r.warnings.length) {
    body.push(h1('Scan warnings'));
    r.warnings.forEach((w) => body.push(new Paragraph({ children: [run(`•  ${w}`, { size: 20 })], indent: { left: 400, hanging: 200 }, spacing: { after: 60 } })));
  }
  body.push(para([run('Backup policy = AWS Backup plan or Data Lifecycle Manager (DLM) policy covering the instance or its volumes. "Manual only" means snapshots/AMIs exist but no policy automates them.', { size: 18, color: '52606D' })], { spacing: { before: 300 } }));

  const doc = new Document({
    creator: 'Infosprint Monitoring',
    title: `AWS Security & Backup Report - ${r.client.name}`,
    styles: { default: { document: { run: { font: FONT, size: 21 } } } },
    sections: [{
      properties: { page: { size: { width: 11906, height: 16838, orientation: PageOrientation.LANDSCAPE }, margin: { top: 1000, bottom: 1000, left: 1000, right: 1000 } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [run(`${r.client.name} · ${r.client.accountId} · Page `, { size: 16, color: '52606D' }), new TextRun({ children: [PageNumber.CURRENT], size: 16, font: FONT, color: '52606D' })] })] }) },
      children: body,
    }],
  });
  return Packer.toBuffer(doc);
}

module.exports = { buildDocx };
